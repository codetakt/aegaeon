//! A local password form cannot complete a continuation bound to a verified upstream login.
use super::*;
use crate::organizations::authentication::OriginalAuthentication;
use crate::upstream::UpstreamAuthRequest;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProviderBinding {
    environment: uuid::Uuid,
    connection: uuid::Uuid,
    issuer: String,
    client: String,
    subject: String,
    user: uuid::Uuid,
    link: uuid::Uuid,
    link_revision: i64,
    upstream_subject_hash: String,
}
impl From<&OriginalAuthentication> for ProviderBinding {
    fn from(fact: &OriginalAuthentication) -> Self {
        Self {
            environment: fact.context.environment_id,
            connection: fact.context.connection_id,
            issuer: fact.issuer.clone(),
            client: fact.upstream_client_id.clone(),
            subject: fact.subject.clone(),
            user: fact.user_id,
            link: fact.account_link_id,
            link_revision: fact.account_link_revision,
            upstream_subject_hash: fact.upstream_subject_hash.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FederatedRequest {
    authorization: Value,
    upstream_reauthentication: ProviderBinding,
    previous_auth_time: i64,
}

pub(super) fn pack(request: Value, prior: &OriginalAuthentication) -> Result<Value, Response> {
    serde_json::to_value(FederatedRequest {
        authorization: request,
        upstream_reauthentication: prior.into(),
        previous_auth_time: prior.auth_time,
    })
    .map_err(|_| unavailable())
}

pub(super) fn authorization(stored: &Value) -> Result<&Value, Response> {
    if stored.get("upstream_reauthentication").is_some() {
        stored.get("authorization").ok_or_else(invalid)
    } else {
        Ok(stored)
    }
}

pub(in crate::web) async fn sign_in_path(
    state: &AppState,
    prior: &OriginalAuthentication,
) -> Result<String, Response> {
    let mut connection =
        crate::dcr_persistence::admitted_connection::AdmittedConnection::acquire(&state.db_pool)
            .await
            .map_err(|_| unavailable())?;
    let identifier: Option<String> = sqlx::query_scalar("SELECT c.connection_identifier
        FROM aegaeon.active_runtime_environments rt JOIN aegaeon.connections c
        ON c.environment_id=rt.environment_id AND c.configuration_version_id=rt.configuration_version_id
        WHERE rt.environment_id=$1 AND c.id=$2 AND c.status='ACTIVE' AND c.connection_type='OIDC'
        AND c.issuer_url=$3 AND c.client_id=$4")
        .bind(state.environment_id).bind(prior.context.connection_id).bind(&prior.issuer).bind(&prior.upstream_client_id)
        .fetch_optional(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())?;
    connection.release().await;
    let identifier = identifier.ok_or_else(invalid)?;
    let mut endpoint = url::Url::parse(&state.issuer).map_err(|_| unavailable())?;
    endpoint
        .path_segments_mut()
        .map_err(|()| unavailable())?
        .clear()
        .extend(["oauth", "upstream", &identifier, "authorize"]);
    Ok(endpoint.path().to_string())
}

pub(in crate::web) fn continuation_token(target: Option<&str>) -> Result<Option<String>, Response> {
    match target.filter(|value| value.starts_with("/authorize?aeg_login_continue=")) {
        Some(value) => continuation(value),
        None => Ok(None),
    }
}

pub(in crate::web) async fn complete(
    state: &AppState,
    headers: &HeaderMap,
    request: &UpstreamAuthRequest,
    sid: &str,
) -> Result<(), Response> {
    let Some(token) = continuation_token(request.return_to.as_deref())? else {
        return Ok(());
    };
    let browser = browser_cookie(headers)?;
    let pending = storage::load(state, &token, &browser, None).await?;
    let stored: FederatedRequest =
        serde_json::from_value(pending.snapshot.clone()).map_err(|_| invalid())?;
    let ctx = rebuild(state, &pending, pending.id.to_string()).await?;
    let session = state
        .browser_auth
        .auth_sessions
        .try_get_async(sid.to_owned())
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(invalid)?;
    let fact = session
        .original_authentication
        .as_ref()
        .ok_or_else(invalid)?;
    let acr = super::super::authorize_endpoint::authorize_selected_acr(state, &ctx, &state.issuer)?;
    let started = request
        .issued_at
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_secs();
    if session.auth_time_epoch_secs < started
        || request.context.connection_id != fact.context.connection_id
        || ProviderBinding::from(fact) != stored.upstream_reauthentication
        || fact.auth_time <= stored.previous_auth_time
        || u64::try_from(fact.auth_time).ok() != Some(session.auth_time_epoch_secs)
        || acr
            .as_ref()
            .is_some_and(|required| fact.acr.as_ref() != Some(required))
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "login_required",
            "the upstream provider did not establish fresh authentication",
        ));
    }
    // The callback has already consumed its browser-bound upstream state. This
    // separate receipt still requires the original issuer browser cookie, verified
    // connection, linked subject and signed upstream authentication time.
    storage::complete(
        state,
        &pending,
        &token,
        &browser,
        None,
        &session_snapshot(sid, &session),
    )
    .await
}
