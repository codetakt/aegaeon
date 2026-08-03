use crate::management::types::PolicyDocument;

use super::NumericPolicyField;

pub(super) fn token_and_oidc_fields(policy: &PolicyDocument) -> [NumericPolicyField; 7] {
    [
        (
            "jwt_introspection_exp_seconds",
            policy.jwt_introspection_exp_seconds,
        ),
        (
            "oidc_logout_session_ttl_seconds",
            policy.oidc_logout_session_ttl_seconds,
        ),
        (
            "oidc_backchannel_logout_timeout_seconds",
            policy.oidc_backchannel_logout_timeout_seconds,
        ),
        (
            "access_token_time_to_live_seconds",
            policy.access_token_time_to_live_seconds,
        ),
        (
            "id_token_time_to_live_seconds",
            policy.id_token_time_to_live_seconds,
        ),
        (
            "refresh_token_time_to_live_seconds",
            policy.refresh_token_time_to_live_seconds,
        ),
        (
            "authorization_code_time_to_live_seconds",
            policy.authorization_code_time_to_live_seconds,
        ),
    ]
}
