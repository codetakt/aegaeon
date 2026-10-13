use super::{model::*, store, LtiError};
use crate::authcode::types::BearerTokenMeta;
use crate::runtime_configuration::RuntimeAuthorityRevision;
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeSet;
use uuid::Uuid;

pub(crate) fn digest(value: &str) -> String {
    aegaeon_crypto::hash::sha256_hex(value.as_bytes())
}

pub(crate) fn random() -> String {
    aegaeon_crypto::rand::random_base64url(32)
}

pub(crate) async fn now(tx: &mut Transaction<'_, Postgres>) -> Result<i64, LtiError> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut **tx)
            .await?,
    )
}

pub(crate) struct Intent {
    pub id: Uuid,
    pub client_id: String,
    pub registration_id: Uuid,
    pub revision: i64,
    pub runtime_revision: Uuid,
    pub runtime_fingerprint: String,
    pub owner: Uuid,
    pub subject: String,
    pub producer: BearerTokenMeta,
    pub deployment_id: String,
    pub resource_link_id: String,
    pub roles: BTreeSet<String>,
    pub status: String,
    pub session_hash: Option<String>,
    pub csrf_hash: Option<String>,
    pub login_hint_hash: Option<String>,
    pub message_hint_hash: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub authorization_request: Option<Value>,
}

pub(crate) enum Ticket {
    Browser,
    Message,
    Continuation,
}

pub(crate) async fn load(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    ticket: &str,
    kind: Ticket,
) -> Result<Intent, LtiError> {
    if ticket.len() != 43
        || !ticket
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(LtiError::Denied);
    }
    let column = match kind {
        Ticket::Browser => "ticket_hash",
        Ticket::Message => "message_hint_hash",
        Ticket::Continuation => "continuation_hash",
    };
    let sql=format!("SELECT i.*,r.client_id FROM aegaeon.lti_launch_intents i JOIN aegaeon.lti_registrations r ON r.id=i.registration_id WHERE i.environment_id=$1 AND i.{column}=$2 FOR UPDATE OF i");
    let row = sqlx::query(&sql)
        .bind(environment)
        .bind(digest(ticket))
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(LtiError::Denied)?;
    Ok(Intent {
        id: row.try_get("id")?,
        client_id: row.try_get("client_id")?,
        registration_id: row.try_get("registration_id")?,
        revision: row.try_get("revision")?,
        runtime_revision: row.try_get("runtime_revision")?,
        runtime_fingerprint: row.try_get("runtime_fingerprint")?,
        owner: row.try_get("owner_id")?,
        subject: row.try_get("subject")?,
        producer: serde_json::from_value(row.try_get("producer_metadata")?)
            .map_err(|_| LtiError::Unavailable)?,
        deployment_id: row.try_get("deployment_id")?,
        resource_link_id: row.try_get("resource_link_id")?,
        roles: serde_json::from_value(row.try_get("roles")?).map_err(|_| LtiError::Unavailable)?,
        status: row.try_get("status")?,
        session_hash: row.try_get("session_hash")?,
        csrf_hash: row.try_get("csrf_hash")?,
        login_hint_hash: row.try_get("login_hint_hash")?,
        message_hint_hash: row.try_get("message_hint_hash")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        authorization_request: row.try_get("authorization_request")?,
    })
}

pub(crate) async fn owner(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    user: Uuid,
) -> Result<String, LtiError> {
    // The caller must hold the shared subject namespace capability. Permanent
    // reservations are enforced by that substrate's protected database triggers.
    let subject=sqlx::query_scalar("SELECT subject FROM aegaeon.end_users WHERE environment_id=$1 AND id=$2 AND status='ACTIVE' FOR SHARE")
        .bind(environment).bind(user).fetch_optional(&mut **tx).await?.ok_or(LtiError::Denied)?;
    Ok(subject)
}

pub(crate) async fn create(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    runtime: &RuntimeAuthorityRevision,
    registration: &store::Registration,
    request: &CreateLaunch,
    meta: &BearerTokenMeta,
) -> Result<String, LtiError> {
    let user = Uuid::parse_str(&request.user_id).map_err(|_| LtiError::Invalid)?;
    let subject = owner(tx, environment, user).await?;
    let (deployment, link) = registration
        .configuration
        .placement(&request.deployment_id, &request.resource_link_id)?;
    if !deployment.producers.contains(&meta.client_id)
        || !request.roles.is_subset(&deployment.allowed_roles)
        || !super::validation::roles(&request.roles)
    {
        return Err(LtiError::Denied);
    }
    let time = now(tx).await?;
    // The environment lock serializes admission. Count all recent intents,
    // including consumed/cancelled ones, so completion cannot refund the budget.
    let counts:(i64,i64)=sqlx::query_as("SELECT count(*),count(*) FILTER (WHERE producer_client_id=$2 AND owner_id=$3) FROM aegaeon.lti_launch_intents WHERE environment_id=$1 AND created_at > $4")
        .bind(environment).bind(&meta.client_id).bind(user).bind(time-INTENT_TTL_SECONDS).fetch_one(&mut **tx).await?;
    if counts.0 >= 4096 || counts.1 >= 32 {
        return Err(LtiError::Capacity);
    }
    // Keep even early-expired intents until their admission window ends.
    // Bound cleanup work and remove expired sensitive request snapshots. Durable
    // audit events and permanent registration/placement identities remain intact.
    sqlx::query("DELETE FROM aegaeon.lti_launch_intents WHERE id IN (SELECT id FROM aegaeon.lti_launch_intents WHERE environment_id=$1 AND expires_at<=$2 AND created_at<=$3 ORDER BY expires_at LIMIT 512)")
        .bind(environment).bind(time).bind(time-INTENT_TTL_SECONDS).execute(&mut **tx).await?;
    let token_expiry = i64::try_from(
        meta.expires_at
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| LtiError::Denied)?
            .as_secs(),
    )
    .map_err(|_| LtiError::Denied)?;
    let expiry = time
        .checked_add(INTENT_TTL_SECONDS)
        .ok_or(LtiError::Unavailable)?
        .min(token_expiry);
    if expiry <= time {
        return Err(LtiError::Denied);
    }
    let ticket = random();
    // Retain the current grant and binding, never an access-token credential.
    let mut authority = meta.clone();
    authority.token_id.clear();
    authority.application_grant = None;
    let value = serde_json::to_value(&authority).map_err(|_| LtiError::Unavailable)?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.lti_launch_intents(id,environment_id,registration_id,revision,runtime_revision,runtime_fingerprint,owner_id,subject,producer_client_id,producer_token_digest,producer_metadata,deployment_id,resource_link_id,roles,ticket_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)")
        .bind(id).bind(environment).bind(registration.id).bind(registration.active_revision.ok_or(LtiError::Denied)?)
        .bind(runtime.active_configuration_version_id()).bind(runtime.active_configuration_document_fingerprint())
        .bind(user).bind(subject).bind(&meta.client_id).bind(digest(&meta.token_id)).bind(value)
        .bind(&deployment.id).bind(&link.id).bind(json!(request.roles)).bind(digest(&ticket)).bind(time).bind(expiry)
        .execute(&mut **tx).await?;
    store::audit(
        tx,
        environment,
        &meta.client_id,
        "CLIENT",
        id,
        "lti.launch.created.v1",
        json!({"registrationId":registration.id,"revision":registration.active_revision}),
    )
    .await?;
    Ok(ticket)
}
