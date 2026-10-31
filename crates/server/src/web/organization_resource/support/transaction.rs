use super::*;
pub(super) async fn execute(
    state: &AppState,
    admission: &ResourceAdmission,
    scope: Scope,
    meta: &BearerTokenMeta,
    action: Action,
    request_id: &str,
) -> Result<service::Grant, Response> {
    let expected = super::super::super::organization_authority::projection(state)?;
    let started = token::now(state)?;
    let (original, binding, parent) = token::parent(meta, &state.issuer, scope, started)
        .map_err(|_| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let deadline = token::root_deadline(state, admission, meta).await?;
    if deadline <= started {
        return Err(error(state, StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    let context = service::Context {
        original,
        binding: &binding,
        parent_expires_at: parent.min(deadline),
        now: started,
    };
    let mut connection = admission
        .0
        .connection(&state.db_pool)
        .await
        .map_err(|_| unavailable(state))?;
    let mut tx = connection
        .as_mut()
        .map_err(|_| unavailable(state))?
        .begin()
        .await
        .map_err(|_| unavailable(state))?;
    let creating = matches!(&action, Action::Create(..));
    if creating {
        crate::organizations::selected::lock_primary_scope(&mut tx, scope)
            .await
            .map_err(|e| members::storage_error(state, &e))?;
        crate::organizations::repository::lock_domain(&mut tx, scope)
            .await
            .map_err(|e| members::storage_error(state, &e))?;
        let client =
            crate::organizations::consent::client(&mut tx, scope, &meta.client_id, &meta.audience)
                .await
                .map_err(|e| members::storage_error(state, &e))?;
        let management:Option<bool>=sqlx::query_scalar("SELECT management FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 AND audience=$3 COLLATE \"C\" FOR SHARE")
            .bind(scope.environment_id).bind(scope.domain_id).bind(&meta.audience).fetch_optional(&mut *tx).await.map_err(|_|unavailable(state))?;
        if client.id != original.consent.client_binding_id
            || client.revision != original.consent.client_binding_revision
            || management != Some(true)
            || !client.targets.iter().any(|t| {
                t.audience == meta.audience && t.privileges.iter().any(|p| p == service::PRIVILEGE)
            })
        {
            return Err(error(state, StatusCode::FORBIDDEN, "insufficient_scope"));
        }
    }
    let grant = match action {
        Action::Create(value, key) => {
            service::activate(&mut tx, &context, &value, &key, request_id).await
        }
        Action::Read(id) => service::read(&mut tx, &context, id).await,
        Action::Revoke(value, key) => {
            service::revoke(&mut tx, &context, &value, &key, request_id).await
        }
    }
    .map_err(|e| members::storage_error(state, &e))?;
    super::super::super::organization_authority::recheck_projection(state, &mut tx, &expected)
        .await?;
    let now = token::now(state)?;
    let current_deadline = token::root_deadline(state, admission, meta).await?;
    if now < started
        || now >= parent
        || now >= current_deadline
        || (creating && (now >= grant.expires_at || grant.expires_at > current_deadline))
    {
        return Err(error(state, StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    admission.0.admit_commit().map_err(|_| unavailable(state))?;
    tx.commit().await.map_err(|_| unavailable(state))?;
    connection.release().await;
    Ok(grant)
}
