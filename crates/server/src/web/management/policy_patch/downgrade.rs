use crate::management::types::{PolicyDocument, PolicySenderConstraint};
use axum::{http::StatusCode, response::Response};
use std::collections::BTreeSet;

type PolicyBoolGetter = fn(&PolicyDocument) -> bool;
type PolicyBoolField = (&'static str, PolicyBoolGetter);
type PolicyU32Getter = fn(&PolicyDocument) -> u32;
type PolicyU32Field = (&'static str, PolicyU32Getter);
type PolicyStringSliceGetter = fn(&PolicyDocument) -> &[String];
type PolicyStringListField = (&'static str, PolicyStringSliceGetter);

// Security-critical boolean fields require explicit downgrade acknowledgement.
const SECURITY_CRITICAL_BOOLEANS: &[PolicyBoolField] = &[
    ("pkce_required", |p| p.pkce_required),
    ("require_state_parameter", |p| p.require_state_parameter),
    ("strict_authorize_redirect", |p| p.strict_authorize_redirect),
    ("require_scope_subset", |p| p.require_scope_subset),
    ("require_audience_match", |p| p.require_audience_match),
    ("retain_refresh_chain", |p| p.retain_refresh_chain),
    ("enforce_refresh_sender_binding", |p| {
        p.enforce_refresh_sender_binding
    }),
    ("dpop_strict", |p| p.dpop_strict),
    ("require_pushed_authorization_requests", |p| {
        p.require_pushed_authorization_requests
    }),
    ("require_client_auth_token", |p| p.require_client_auth_token),
    ("require_client_auth_par", |p| p.require_client_auth_par),
    ("require_client_auth_introspection", |p| {
        p.require_client_auth_introspection
    }),
    ("require_client_auth_revocation", |p| {
        p.require_client_auth_revocation
    }),
    ("dpop_require_nonce", |p| p.dpop_require_nonce),
    ("client_jwt_require_kid", |p| p.client_jwt_require_kid),
    ("dcr_require_pkce_for_public", |p| {
        p.dcr_require_pkce_for_public
    }),
    ("dcr_require_pkce_for_confidential", |p| {
        p.dcr_require_pkce_for_confidential
    }),
    ("dcr_require_sender_constrained", |p| {
        p.dcr_require_sender_constrained
    }),
    ("oidc_require_nonce", |p| p.oidc_require_nonce),
];

// Enabling these capabilities expands externally reachable protocol surface.
const SECURITY_SURFACE_ENABLE_BOOLEANS: &[PolicyBoolField] = &[
    ("dcr_enabled", |p| p.dcr_enabled),
    ("private_key_jwt_enabled", |p| p.private_key_jwt_enabled),
    ("jwt_access_tokens_enabled", |p| p.jwt_access_tokens_enabled),
    ("jwt_introspection_enabled", |p| p.jwt_introspection_enabled),
];

const SECURITY_RELAXING_BOOLEANS: &[PolicyBoolField] = &[
    ("jwt_bearer_allow_client_subject", |p| {
        p.jwt_bearer_allow_client_subject
    }),
    ("jwks_allow_kid_reuse", |p| p.jwks_allow_kid_reuse),
];

const SECURITY_RELAXING_U32_INCREASES: &[PolicyU32Field] = &[
    ("dpop_iat_window_seconds", |p| p.dpop_iat_window_seconds),
    ("dpop_nonce_ttl_seconds", |p| p.dpop_nonce_ttl_seconds),
    ("par_expires_in_seconds", |p| p.par_expires_in_seconds),
    ("device_code_ttl_seconds", |p| p.device_code_ttl_seconds),
    ("activation_token_default_ttl_seconds", |p| {
        p.activation_token_default_ttl_seconds
    }),
    ("password_reset_token_default_ttl_seconds", |p| {
        p.password_reset_token_default_ttl_seconds
    }),
    ("recovery_token_max_ttl_seconds", |p| {
        p.recovery_token_max_ttl_seconds
    }),
    ("client_secret_default_expiration_days", |p| {
        p.client_secret_default_expiration_days
    }),
    ("client_secret_max_expiration_days", |p| {
        p.client_secret_max_expiration_days
    }),
    ("jwt_leeway_seconds", |p| p.jwt_leeway_seconds),
    ("pkjwt_jti_window_seconds", |p| p.pkjwt_jti_window_seconds),
    ("jwt_bearer_jti_window_seconds", |p| {
        p.jwt_bearer_jti_window_seconds
    }),
    ("request_object_jti_ttl_seconds", |p| {
        p.request_object_jti_ttl_seconds
    }),
    ("jwt_introspection_exp_seconds", |p| {
        p.jwt_introspection_exp_seconds
    }),
    ("ssa_leeway_seconds", |p| p.ssa_leeway_seconds),
    ("oidc_logout_session_ttl_seconds", |p| {
        p.oidc_logout_session_ttl_seconds
    }),
    ("jose_header_max_len", |p| p.jose_header_max_len),
    ("jwks_cache_ttl_seconds", |p| p.jwks_cache_ttl_seconds),
    ("jwks_shared_state_max_age_seconds", |p| {
        p.jwks_shared_state_max_age_seconds
    }),
    ("jwks_max_body_bytes", |p| p.jwks_max_body_bytes),
    ("federation_entity_cache_ttl_seconds", |p| {
        p.federation_entity_cache_ttl_seconds
    }),
    ("federation_trust_chain_cache_ttl_seconds", |p| {
        p.federation_trust_chain_cache_ttl_seconds
    }),
    ("upstream_discovery_cache_ttl_seconds", |p| {
        p.upstream_discovery_cache_ttl_seconds
    }),
    ("upstream_jwks_cache_ttl_seconds", |p| {
        p.upstream_jwks_cache_ttl_seconds
    }),
    ("access_token_time_to_live_seconds", |p| {
        p.access_token_time_to_live_seconds
    }),
    ("id_token_time_to_live_seconds", |p| {
        p.id_token_time_to_live_seconds
    }),
    ("refresh_token_time_to_live_seconds", |p| {
        p.refresh_token_time_to_live_seconds
    }),
    ("authorization_code_time_to_live_seconds", |p| {
        p.authorization_code_time_to_live_seconds
    }),
    ("auth_session_ttl_seconds", |p| p.auth_session_ttl_seconds),
    ("auth_max_sessions", |p| p.auth_max_sessions),
    ("stepup_challenge_ttl_seconds", |p| {
        p.stepup_challenge_ttl_seconds
    }),
    ("upstream_auth_ttl_seconds", |p| p.upstream_auth_ttl_seconds),
    ("upstream_logout_relay_ttl_seconds", |p| {
        p.upstream_logout_relay_ttl_seconds
    }),
];

const SECURITY_RELAXING_U32_DECREASES: &[PolicyU32Field] =
    &[("device_code_poll_interval_seconds", |p| {
        p.device_code_poll_interval_seconds
    })];

// Capacity and retry increases can weaken availability/DoS posture even when
// they do not relax a protocol invariant.
const RESOURCE_RISK_U32_INCREASES: &[PolicyU32Field] = &[
    ("jwks_circuit_open_fails", |p| p.jwks_circuit_open_fails),
    ("jwks_http_timeout_seconds", |p| p.jwks_http_timeout_seconds),
    ("jwks_http_retries", |p| p.jwks_http_retries),
    ("jwks_local_cache_max_entries", |p| {
        p.jwks_local_cache_max_entries
    }),
    ("federation_cache_max_entries", |p| {
        p.federation_cache_max_entries
    }),
    ("upstream_discovery_cache_max_entries", |p| {
        p.upstream_discovery_cache_max_entries
    }),
    ("upstream_jwks_cache_max_entries", |p| {
        p.upstream_jwks_cache_max_entries
    }),
];

const SECURITY_LIST_EXPANSIONS: &[PolicyStringListField] = &[
    ("allowed_grant_types", |p| &p.allowed_grant_types),
    ("allowed_signing_algorithms", |p| {
        &p.allowed_signing_algorithms
    }),
    ("client_jwt_allowed_algs", |p| &p.client_jwt_allowed_algs),
    ("dcr_allowed_sender_methods", |p| {
        &p.dcr_allowed_sender_methods
    }),
];

const OUTBOUND_ALLOWLIST_RELAXATIONS: &[PolicyStringListField] = &[
    ("federation_outbound_allowed_domains", |p| {
        &p.federation_outbound_allowed_domains
    }),
    ("upstream_outbound_allowed_domains", |p| {
        &p.upstream_outbound_allowed_domains
    }),
];

pub(in crate::web::management) fn detect_security_downgrade(
    before: &PolicyDocument,
    after: &PolicyDocument,
) -> Vec<&'static str> {
    let mut downgrades = SECURITY_CRITICAL_BOOLEANS
        .iter()
        .filter(|(_, getter)| getter(before) && !getter(after))
        .chain(
            SECURITY_RELAXING_BOOLEANS
                .iter()
                .filter(|(_, getter)| !getter(before) && getter(after)),
        )
        .chain(
            SECURITY_SURFACE_ENABLE_BOOLEANS
                .iter()
                .filter(|(_, getter)| !getter(before) && getter(after)),
        )
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();
    downgrades.extend(
        SECURITY_RELAXING_U32_INCREASES
            .iter()
            .filter(|(_, getter)| getter(after) > getter(before))
            .map(|(name, _)| *name),
    );
    downgrades.extend(
        SECURITY_RELAXING_U32_DECREASES
            .iter()
            .filter(|(_, getter)| getter(after) < getter(before))
            .map(|(name, _)| *name),
    );
    downgrades.extend(
        RESOURCE_RISK_U32_INCREASES
            .iter()
            .filter(|(_, getter)| getter(after) > getter(before))
            .map(|(name, _)| *name),
    );
    downgrades.extend(
        SECURITY_LIST_EXPANSIONS
            .iter()
            .filter(|(_, getter)| normalized_set_adds_value(getter(before), getter(after)))
            .map(|(name, _)| *name),
    );
    downgrades.extend(
        OUTBOUND_ALLOWLIST_RELAXATIONS
            .iter()
            .filter(|(_, getter)| outbound_allowlist_relaxed(getter(before), getter(after)))
            .map(|(name, _)| *name),
    );
    if sender_constraint_strength(after.sender_constraint)
        < sender_constraint_strength(before.sender_constraint)
    {
        downgrades.push("sender_constraint");
    }
    downgrades
}

fn normalized_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn normalized_set_adds_value(before: &[String], after: &[String]) -> bool {
    let before = normalized_set(before);
    let after = normalized_set(after);
    after.difference(&before).next().is_some()
}

fn outbound_allowlist_relaxed(before: &[String], after: &[String]) -> bool {
    let before = normalized_set(before);
    let after = normalized_set(after);
    (!before.is_empty() && after.is_empty()) || after.difference(&before).next().is_some()
}

#[derive(Clone, Copy, Debug)]
pub(in crate::web::management) struct SecurityDowngradeAuthorization<'a> {
    pub(in crate::web::management) allowed: bool,
    pub(in crate::web::management) reason: Option<&'a str>,
}

pub(in crate::web::management) fn require_security_downgrade_authorization(
    before: &PolicyDocument,
    after: &PolicyDocument,
    authorization: SecurityDowngradeAuthorization<'_>,
    request_id: &str,
) -> Result<Vec<&'static str>, Response> {
    let downgraded_fields = detect_security_downgrade(before, after);
    if downgraded_fields.is_empty() {
        return Ok(downgraded_fields);
    }

    if !authorization.allowed {
        return Err(security_downgrade_error(
            "security_downgrade_rejected",
            &format!(
                "Security or resource-risk downgrade detected for: {}. Set allowSecurityDowngrade=true and provide a non-empty reason to proceed.",
                downgraded_fields.join(", "),
            ),
            request_id,
        ));
    }

    if authorization
        .reason
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return Err(security_downgrade_error(
            "security_downgrade_reason_required",
            &format!(
                "Security or resource-risk downgrade detected for: {}. Provide a non-empty reason when allowSecurityDowngrade=true.",
                downgraded_fields.join(", "),
            ),
            request_id,
        ));
    }

    Ok(downgraded_fields)
}

fn security_downgrade_error(error_code: &str, message: &str, request_id: &str) -> Response {
    super::super::error_response(
        StatusCode::CONFLICT,
        error_code,
        message,
        None,
        Some(request_id),
    )
}

const fn sender_constraint_strength(value: PolicySenderConstraint) -> u8 {
    match value {
        PolicySenderConstraint::None => 0,
        PolicySenderConstraint::Dpop => 1,
        PolicySenderConstraint::Mtls => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn downgraded_policy() -> (PolicyDocument, PolicyDocument) {
        let before = PolicyDocument::default();
        let mut after = before.clone();
        after.pkce_required = false;
        (before, after)
    }

    #[test]
    fn downgrade_authorization_rejects_missing_acknowledgement() {
        let (before, after) = downgraded_policy();

        let response = require_security_downgrade_authorization(
            &before,
            &after,
            SecurityDowngradeAuthorization {
                allowed: false,
                reason: Some("intentional test downgrade"),
            },
            "req-1",
        )
        .expect_err("missing acknowledgement must be rejected");

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn downgrade_authorization_requires_non_empty_reason() {
        let (before, after) = downgraded_policy();

        for reason in [None, Some(""), Some("   ")] {
            assert!(require_security_downgrade_authorization(
                &before,
                &after,
                SecurityDowngradeAuthorization {
                    allowed: true,
                    reason,
                },
                "req-1",
            )
            .is_err());
        }
    }

    #[test]
    fn downgrade_authorization_returns_detected_fields_when_acknowledged() {
        let (before, after) = downgraded_policy();

        let downgraded_fields = require_security_downgrade_authorization(
            &before,
            &after,
            SecurityDowngradeAuthorization {
                allowed: true,
                reason: Some("temporary interoperability test"),
            },
            "req-1",
        )
        .expect("downgrade should be acknowledged");

        assert_eq!(downgraded_fields, vec!["pkce_required"]);
    }
}
