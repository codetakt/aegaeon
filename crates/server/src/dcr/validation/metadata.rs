use std::collections::HashSet;
use std::hash::BuildHasher;

use super::super::registration::ClientRegistration;
use super::jwks::{runtime_supported_client_jwt_alg, validate_inline_jwks};
use super::uris::{validate_jwks_uri, validate_redirect_uris, validate_server_callback_uri};
use super::{reject_bcp, with_bcp_metric};

pub(super) fn validate_registration_uris(meta: &ClientRegistration) -> Result<(), String> {
    if let Some(ref uris) = meta.redirect_uris {
        with_bcp_metric("redirect_invalid", validate_redirect_uris(uris))?;
    }
    if let Some(ref uris) = meta.post_logout_redirect_uris {
        with_bcp_metric("post_logout_redirect_invalid", validate_redirect_uris(uris))?;
    }
    if let Some(ref uri) = meta.backchannel_logout_uri {
        with_bcp_metric(
            "backchannel_logout_uri_invalid",
            validate_server_callback_uri(uri, "backchannel_logout_uri"),
        )?;
    }
    if meta.backchannel_logout_session_required == Some(true)
        && meta
            .backchannel_logout_uri
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return reject_bcp(
            "backchannel_logout_uri_invalid",
            "backchannel_logout_session_required requires backchannel_logout_uri",
        );
    }
    Ok(())
}

pub(super) fn validate_registration_scope(meta: &ClientRegistration) -> Result<(), String> {
    let Some(scope) = meta.scope.as_deref() else {
        return Ok(());
    };
    with_bcp_metric(
        "scope_invalid",
        crate::oauth_scope::parse_scope_string(scope)
            .map(|_| ())
            .map_err(|err| format!("scope is invalid: {err}")),
    )
}

pub(super) fn validate_client_key_material<S: BuildHasher>(
    meta: &ClientRegistration,
    require_kid: bool,
    allowed_algs: &HashSet<String, S>,
    method_normalized: &str,
) -> Result<(), String> {
    if let Some(jwks_uri) = meta.jwks_uri.as_deref() {
        with_bcp_metric("jwks_uri_invalid", validate_jwks_uri(jwks_uri))?;
    }
    if let Some(jwks_value) = meta.jwks.clone() {
        validate_inline_jwks(jwks_value, require_kid)?;
    }
    if method_normalized != "private_key_jwt" {
        return Ok(());
    }

    validate_private_key_jwt_alg_policy(meta, allowed_algs)?;
    validate_private_key_jwt_key_source(meta)
}

fn validate_private_key_jwt_alg_policy<S: BuildHasher>(
    meta: &ClientRegistration,
    allowed_algs: &HashSet<String, S>,
) -> Result<(), String> {
    if !allowed_algs
        .iter()
        .any(|alg| runtime_supported_client_jwt_alg(alg).is_some())
    {
        return reject_bcp(
            "alg_not_supported",
            "private_key_jwt requires a promoted RS256 or PS256 client assertion alg",
        );
    }

    let Some(ref alg) = meta.token_endpoint_auth_signing_alg else {
        return Ok(());
    };
    let normalized = alg.trim().to_ascii_uppercase();
    if !allowed_algs.contains(&normalized) {
        return reject_bcp("alg_not_allowed", format!("alg {normalized} not allowed"));
    }
    if runtime_supported_client_jwt_alg(&normalized).is_none() {
        return reject_bcp(
            "alg_not_supported",
            format!("alg {normalized} is not supported for client JWT authentication"),
        );
    }
    Ok(())
}

fn validate_private_key_jwt_key_source(meta: &ClientRegistration) -> Result<(), String> {
    let has_remote_key_source = meta
        .jwks_uri
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let has_inline_key_source = meta.jwks.is_some();
    if has_remote_key_source || has_inline_key_source {
        Ok(())
    } else {
        reject_bcp(
            "key_source_missing",
            "private_key_jwt requires jwks_uri or jwks",
        )
    }
}

pub(super) fn validate_id_token_signed_response_alg(
    meta: &ClientRegistration,
) -> Result<(), String> {
    let Some(ref requested_alg) = meta.id_token_signed_response_alg else {
        return Ok(());
    };
    let normalized = requested_alg.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return reject_bcp(
            "oidc_id_token_alg_blank",
            "id_token_signed_response_alg must not be blank",
        );
    }
    if normalized == "RS256" {
        Ok(())
    } else {
        reject_bcp(
            "oidc_id_token_alg_not_allowed",
            format!("id_token_signed_response_alg {normalized} is not supported (only RS256)"),
        )
    }
}
