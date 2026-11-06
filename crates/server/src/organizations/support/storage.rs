use super::*;

pub(super) async fn load(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: Uuid,
) -> Result<Grant, RepositoryError> {
    let row=sqlx::query("SELECT id,authority,revision,active,issued_at,expires_at FROM aegaeon.organization_admin_access_grants WHERE environment_id=$1 AND domain_id=$2 AND id=$3 FOR UPDATE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(id).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let grant = Grant {
        id: row.try_get("id")?,
        authority: serde_json::from_value(row.try_get("authority")?)?,
        revision: row.try_get("revision")?,
        active: row.try_get("active")?,
        issued_at: row.try_get("issued_at")?,
        expires_at: row.try_get("expires_at")?,
    };
    grant.validate()?;
    require(grant.authority.binding.scope == scope)?;
    Ok(grant)
}

pub(crate) async fn read(
    tx: &mut Transaction<'_, Postgres>,
    context: &Context<'_>,
    id: Uuid,
) -> Result<Grant, RepositoryError> {
    owner(tx, context).await?;
    let grant = load(tx, context.binding.scope, id).await?;
    require(grant.authority.binding == *context.binding)?;
    Ok(grant)
}

pub(super) async fn owner(
    tx: &mut Transaction<'_, Postgres>,
    context: &Context<'_>,
) -> Result<(), RepositoryError> {
    selected::validate_original(context.original, context.binding, context.now)?;
    selected::lock_primary_scope(tx, context.binding.scope).await?;
    // Revocation does not require an enabled policy or domain; serialize writes.
    sqlx::query(
        "SELECT id FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(context.binding.scope.environment_id)
    .bind(context.binding.scope.domain_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(AuthorityError::Forbidden)?;
    identity::require_current(
        tx,
        context.binding,
        context.original.consent.identity_revision,
        context.original.consent.auth_time,
    )
    .await?;
    Ok(())
}

pub(super) async fn event(
    tx: &mut Transaction<'_, Postgres>,
    grant: &Grant,
    request_id: &str,
    reason: &str,
    event_type: &str,
    before_revision: Option<i64>,
) -> Result<(), RepositoryError> {
    let actor = repo::AuditActor {
        basis: Some(
            serde_json::json!({"kind":"administrative_grant","grantId":grant.id,"grantRevision":grant.revision,"operatorGrantId":grant.authority.ceiling.operator_grant_id,"operatorRevision":grant.authority.ceiling.operator_revision,"policyRevision":grant.authority.ceiling.policy_revision,"originalAuthTime":grant.authority.auth_time}),
        ),
        id: grant.authority.ceiling.administrator_id,
        kind: repo::ActorKind::Operator,
        client_id: grant.authority.binding.client_id.clone(),
        client_registration_id: None,
        request_id: request_id.into(),
        reason: reason.into(),
    };
    actor.validate()?;
    let id = Uuid::new_v4();
    let scope = grant.authority.binding.scope;
    let data = serde_json::json!({"grant_id":grant.id,"user_id":grant.authority.binding.user_id,"client_registration_id":grant.authority.binding.client_registration_id,"root_id":grant.authority.binding.root_id,"revision":grant.revision,"active":grant.active,"roles":grant.authority.ceiling.role_versions,"expires_at":grant.expires_at,"before":before_revision.map(|revision| serde_json::json!({"revision":revision})),"after":{"revision":grant.revision},"authorityBasis":actor.basis});
    crate::organizations::audit::retention::validate_data(&data)?;
    sqlx::query("INSERT INTO aegaeon.organization_authority_events(id,environment_id,domain_id,organization_id,actor_id,actor_kind,client_id,request_id,reason,event_type,data,client_registration_id) VALUES($1,$2,$3,$4,$5,'operator',$6,$7,$8,$9,$10,$11)")
        .bind(id).bind(scope.environment_id).bind(scope.domain_id).bind(grant.authority.organization_id).bind(actor.id).bind(&actor.client_id).bind(request_id).bind(reason).bind(event_type).bind(data).bind(grant.authority.binding.client_registration_id).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO aegaeon.organization_authority_outbox(event_id) VALUES($1)")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(super) fn digest<T: Serialize>(value: &T) -> Result<Vec<u8>, RepositoryError> {
    Ok(aegaeon_crypto::hash::sha256_digest(&serde_json::to_vec(value)?).to_vec())
}
pub(super) fn validate_key_reason(key: &str, reason: &str) -> Result<(), AuthorityError> {
    require(
        !key.is_empty()
            && key.len() <= 128
            && key.bytes().all(|b| b.is_ascii_graphic())
            && !reason.trim().is_empty()
            && reason.len() <= 1024
            && !reason.chars().any(char::is_control),
    )
}
