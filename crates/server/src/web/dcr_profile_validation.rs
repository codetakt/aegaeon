mod metadata;
mod profile;
mod software_statement;

use super::AppState;
use axum::response::Response;

use crate::dcr::ClientRegistration;

use metadata::{
    effective_registration_metadata_with_response_types, validate_registration_metadata_or_response,
};
use profile::{resolve_dcr_profile, validate_registration_profile_or_response};
use software_statement::validate_registration_software_statement;

pub(super) async fn validate_registration_policy_or_response(
    state: &AppState,
    issuer_base: &str,
    meta: &ClientRegistration,
    existing: Option<&crate::client_registry::RegisteredClient>,
) -> Result<(), Response> {
    validate_registration_policy_with_existing_response_types_or_response(
        state,
        issuer_base,
        meta,
        existing,
        None,
    )
    .await
}

pub(super) async fn validate_registration_policy_with_existing_response_types_or_response(
    state: &AppState,
    issuer_base: &str,
    meta: &ClientRegistration,
    existing: Option<&crate::client_registry::RegisteredClient>,
    existing_response_types: Option<&[String]>,
) -> Result<(), Response> {
    let effective = effective_registration_metadata_with_response_types(
        meta,
        existing,
        existing_response_types,
    );
    validate_registration_software_statement(
        &state.dcr_validation_config,
        meta,
        &effective,
        issuer_base,
    )?;
    validate_registration_metadata_or_response(state, &effective)?;
    super::dcr_scope::validate_registration_scope_or_response(
        &effective,
        &state.dcr_scope_allowlist,
    )?;
    let profile = resolve_dcr_profile(state, issuer_base).await?;
    validate_registration_profile_or_response(&effective, &profile)
}

#[cfg(test)]
mod tests {
    use super::metadata::effective_registration_metadata;
    use super::metadata::effective_registration_metadata_with_response_types;
    use super::profile::validate_registration_against_profile;
    use crate::dcr::ClientRegistration;
    use crate::oauth_profile;
    use crate::policy::SenderConstraint;

    type TestResult = Result<(), String>;

    fn profile(
        allowed_grant_types: Vec<String>,
        token_endpoint_auth_methods_allowed: Vec<String>,
    ) -> oauth_profile::ResolvedProfile {
        oauth_profile::ResolvedProfile {
            id: "profile-id".to_string(),
            name: "downstream".to_string(),
            require_pkce: false,
            require_state_parameter: true,
            require_iss_parameter: true,
            sender_constrained: SenderConstraint::None,
            enforce_refresh_sender_binding: false,
            allowed_grant_types,
            token_endpoint_auth_methods_allowed,
        }
    }

    fn existing_client(
        allowed_grant_types: Vec<String>,
    ) -> crate::client_registry::RegisteredClient {
        crate::client_registry::RegisteredClient {
            client_id: "client-id".to_string(),
            client_secret: None,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            token_endpoint_auth_method: "private_key_jwt".to_string(),
            jwks_pem: None,
            inline_jwks: None,
            jwks_uri: Some("https://example.com/jwks.json".to_string()),
            token_endpoint_auth_signing_alg: Some("RS256".to_string()),
            allowed_scopes: vec!["read".to_string()],
            allowed_grant_types,
            registration_access_token: Some("rat".to_string()),
            client_id_issued_at: Some(1),
        }
    }

    #[test]
    fn dcr_update_profile_validation_uses_effective_existing_metadata() {
        let meta = ClientRegistration {
            redirect_uris: Some(vec!["https://new.example.com/callback".to_string()]),
            ..ClientRegistration::default()
        };
        let existing = existing_client(vec!["authorization_code".to_string()]);
        let effective = effective_registration_metadata(&meta, Some(&existing));
        let profile = profile(
            vec!["authorization_code".to_string()],
            vec!["private_key_jwt".to_string()],
        );

        assert_eq!(effective.scope, Some("read".to_string()));
        assert!(validate_registration_against_profile(&effective, &profile).is_ok());
    }

    #[test]
    fn dcr_update_profile_validation_preserves_existing_response_types() {
        let meta = ClientRegistration {
            redirect_uris: Some(vec!["https://new.example.com/callback".to_string()]),
            ..ClientRegistration::default()
        };
        let existing = existing_client(vec!["authorization_code".to_string()]);
        let effective = effective_registration_metadata_with_response_types(
            &meta,
            Some(&existing),
            Some(&["code id_token".to_string()]),
        );

        assert_eq!(
            effective.response_types,
            Some(vec!["code id_token".to_string()])
        );
    }

    #[test]
    fn dcr_update_profile_validation_rejects_disallowed_effective_grant() -> TestResult {
        let meta = ClientRegistration {
            redirect_uris: Some(vec!["https://new.example.com/callback".to_string()]),
            ..ClientRegistration::default()
        };
        let existing = existing_client(vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]);
        let effective = effective_registration_metadata(&meta, Some(&existing));
        let profile = profile(
            vec!["authorization_code".to_string()],
            vec!["private_key_jwt".to_string()],
        );

        let err = validate_registration_against_profile(&effective, &profile)
            .err()
            .ok_or_else(|| "refresh_token must be rejected by the profile".to_string())?;
        assert_eq!(err.code, "grant_types_not_allowed");
        Ok(())
    }
}
