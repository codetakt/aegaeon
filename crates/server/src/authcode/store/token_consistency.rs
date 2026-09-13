use crate::authcode::types::{AccessToken, BearerTokenMeta, CnfClaim, RefreshToken, SenderBinding};
use std::collections::HashSet;
use std::time::{Duration, SystemTime};

pub(super) fn sender_bindings_match(
    expected: Option<&SenderBinding>,
    presented: Option<&SenderBinding>,
) -> bool {
    match (expected, presented) {
        (None, None) => true,
        (Some(SenderBinding::DPoP { jkt }), Some(SenderBinding::DPoP { jkt: present })) => {
            crate::util::jwk_thumbprint_matches(jkt, present)
        }
        (
            Some(SenderBinding::Mtls { fingerprint }),
            Some(SenderBinding::Mtls {
                fingerprint: present,
            }),
        ) => fingerprint == present,
        _ => false,
    }
}

fn sender_binding_matches_cnf(
    sender_binding: Option<&SenderBinding>,
    cnf: Option<&CnfClaim>,
) -> bool {
    match (sender_binding, cnf) {
        (None, None) => true,
        (Some(SenderBinding::DPoP { jkt }), Some(CnfClaim::Jkt(present))) => {
            crate::util::jwk_thumbprint_matches(jkt, present)
        }
        (Some(SenderBinding::Mtls { fingerprint }), Some(CnfClaim::X5tS256(present))) => {
            crate::middleware::tls::mtls_fingerprint_to_x5t_s256(fingerprint).as_deref()
                == Some(present.as_str())
        }
        _ => false,
    }
}

pub(super) fn scope_set(scope: Option<&str>) -> HashSet<&str> {
    scope.into_iter().flat_map(str::split_whitespace).collect()
}

pub(super) fn meta_scope_set(meta: &BearerTokenMeta) -> HashSet<&str> {
    meta.granted_scopes.iter().map(String::as_str).collect()
}

pub(super) fn refresh_parent_audience(parent: &RefreshToken) -> &str {
    parent
        .target_context
        .as_ref()
        .map(|context| context.audience.as_str())
        .or(parent.resource.as_deref())
        .unwrap_or(&parent.client_id)
}

pub(crate) fn bearer_metadata_matches_access_token(
    access_token: &AccessToken,
    meta: &BearerTokenMeta,
) -> Result<(), &'static str> {
    if access_token.exchange_root.as_ref()
        != meta.exchange_grant.as_ref().and_then(|grant| grant.root())
    {
        return Err("access token and metadata exchange lineage must match");
    }
    if meta.application_grant.as_ref().is_some_and(|grant| {
        grant.validate().is_err()
            || grant.client_id != meta.client_id
            || grant.subject != meta.user_id
    }) {
        return Err("invalid application authorization context");
    }
    if meta.token_id.as_str() != access_token.token.as_str() {
        return Err("bearer metadata token_id must match the access token");
    }
    if meta.client_id.as_str() != access_token.client_id.as_str() {
        return Err("bearer metadata client_id must match the access token");
    }
    if meta.user_id.as_str() != access_token.user_id.as_str() {
        return Err("bearer metadata user_id must match the access token");
    }
    if scope_set(access_token.scope.as_deref()) != meta_scope_set(meta) {
        return Err("bearer metadata scope must match the access token");
    }
    if !sender_binding_matches_cnf(meta.sender_binding.as_ref(), access_token.cnf.as_ref()) {
        return Err("bearer metadata sender_binding must match the access token confirmation");
    }
    Ok(())
}

pub(super) fn refresh_token_matches_issued_grant(
    refresh_token: &RefreshToken,
    access_token: &AccessToken,
    meta: &BearerTokenMeta,
) -> Result<(), &'static str> {
    // Initial issuance binds both tokens to the same grant. Only refresh may
    // narrow the access token independently (RFC 6749 section 6).
    if scope_set(refresh_token.scope.as_deref()) != scope_set(access_token.scope.as_deref()) {
        return Err("refresh token scope must match the access token");
    }
    refresh_token_covers_access_token(refresh_token, access_token, meta)
}

pub(super) fn refresh_token_covers_access_token(
    refresh_token: &RefreshToken,
    access_token: &AccessToken,
    meta: &BearerTokenMeta,
) -> Result<(), &'static str> {
    let expected_root = refresh_token
        .exchange_grant
        .as_ref()
        .and_then(|grant| grant.root());
    if access_token.exchange_root.as_ref() != expected_root
        || expected_root.is_some_and(|root| {
            meta.expires_at > root.expires_at || refresh_token.expires_at > root.expires_at
        })
    {
        return Err("access token must preserve the refresh lineage and deadline");
    }
    if !crate::application_authorization::is_restriction(
        meta.application_grant.as_ref(),
        refresh_token.application_grant.as_ref(),
    ) {
        return Err("application authority exceeds the refresh grant");
    }
    match (&refresh_token.exchange_grant, &meta.exchange_grant) {
        (None, None) => {}
        (Some(parent), Some(current)) if current.is_restriction_of(parent) => {}
        _ => return Err("access authority must be a restriction of the refresh grant"),
    }
    if refresh_token.client_id.as_str() != access_token.client_id.as_str()
        || refresh_token.user_id.as_str() != access_token.user_id.as_str()
    {
        return Err("refresh token owner must match the access token");
    }
    if !scope_set(access_token.scope.as_deref())
        .is_subset(&scope_set(refresh_token.scope.as_deref()))
    {
        return Err("access token scope must be covered by the refresh token");
    }
    let refresh_audience = refresh_parent_audience(refresh_token);
    if meta.audience.as_str() != refresh_audience {
        return Err("bearer metadata audience must match refresh token resource");
    }
    if !sender_bindings_match(
        refresh_token.sender_binding.as_ref(),
        meta.sender_binding.as_ref(),
    ) {
        return Err("bearer metadata sender_binding must match refresh token");
    }
    Ok(())
}

pub(super) fn token_is_active_revoked(expires_at: Option<SystemTime>, now: SystemTime) -> bool {
    expires_at.is_some_and(|expires_at| expires_at > now)
}

pub(super) fn access_token_expired_at(token: &AccessToken, now: SystemTime) -> bool {
    match token
        .created_at
        .checked_add(Duration::from_secs(token.expires_in))
    {
        Some(expiry) => now >= expiry,
        None => true,
    }
}
