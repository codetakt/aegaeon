use super::*;
use crate::organizations::{consent::RootAuthority, AuthorityError, Binding};
pub(super) fn now(state: &AppState) -> Result<i64, Response> {
    crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| unavailable(state))
}
pub(super) fn parent<'a>(
    meta: &'a BearerTokenMeta,
    issuer: &str,
    scope: Scope,
    now: i64,
) -> Result<(&'a RootAuthority, Binding, i64), AuthorityError> {
    let epoch = |t| {
        crate::util::unix_epoch_secs(t)
            .ok()
            .and_then(|v| i64::try_from(v).ok())
            .ok_or(AuthorityError::Forbidden)
    };
    let issued = epoch(meta.issued_at)?;
    let expires = epoch(meta.expires_at)?;
    let grant = meta
        .exchange_grant
        .as_ref()
        .ok_or(AuthorityError::Forbidden)?;
    let original = grant
        .organization
        .as_ref()
        .ok_or(AuthorityError::Forbidden)?;
    // This is the original authorization token. Its exchange capabilities name
    // permitted destination scopes, not its own source audience/scopes. The
    // authenticated metadata, exact original details and consent/root binding
    // establish this parent; covers_output is for exchanged descendants only.
    if meta.audience != format!("{issuer}/organization-support")
        || meta.granted_scopes.len() != 2
        || !meta.granted_scopes.iter().any(|s| s == service::PRIVILEGE)
        || !meta.granted_scopes.iter().any(|s| s == "offline_access")
        || meta.selected_organization.is_some()
        || meta.application_grant.is_some()
        || meta.client_credentials_grant.is_some()
        || !grant.has_client_scope_ceiling()
        || !grant.original_details_match(meta.authorization_details.as_ref())
        || original.consent.scope != scope
        || meta.auth_time_epoch_secs != Some(original.consent.auth_time)
        || !(1..=300).contains(
            &expires
                .checked_sub(issued)
                .ok_or(AuthorityError::Forbidden)?,
        )
        || now < issued
        || now >= expires
    {
        return Err(AuthorityError::Forbidden);
    }
    let Some(SenderBinding::DPoP { jkt }) = &meta.sender_binding else {
        return Err(AuthorityError::Forbidden);
    };
    let binding = Binding {
        scope,
        issuer: issuer.into(),
        client_id: meta.client_id.clone(),
        client_registration_id: original.consent.client_registration_id,
        subject: meta.user_id.clone(),
        user_id: original.consent.user_id,
        root_id: grant.root().ok_or(AuthorityError::Forbidden)?.id.clone(),
        dpop_jkt: jkt.clone(),
    };
    crate::organizations::selected::validate_original(original, &binding, now)?;
    Ok((original, binding, expires))
}
pub(super) async fn root_deadline(
    state: &AppState,
    admission: &ResourceAdmission,
    meta: &BearerTokenMeta,
) -> Result<i64, Response> {
    let retained = crate::authcode::store::RetainedRoot {
        root: meta
            .exchange_grant
            .as_ref()
            .and_then(|g| g.root())
            .ok_or_else(|| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?
            .clone(),
        refresh_grant: meta.refresh_grant.clone(),
        client: meta.client_id.clone(),
        subject: meta.user_id.clone(),
    };
    let store = state.tokens.store.clone();
    let deadline = admission
        .0
        .blocking(move || store.retained_root_deadline(&retained))
        .await
        .map_err(|_| unavailable(state))?
        .map_err(|_| unavailable(state))?
        .ok_or_else(|| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    crate::util::unix_epoch_secs(deadline)
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| unavailable(state))
}
