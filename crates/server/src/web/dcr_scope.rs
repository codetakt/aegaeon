use axum::response::Response;

use super::dcr_response::invalid_client_metadata_response;
use crate::client_registry::RegisteredClient;
use crate::dcr::ClientRegistration;

fn invalid_scope_response(error: impl std::fmt::Display) -> Response {
    invalid_client_metadata_response(format!("scope is invalid: {error}"))
}

fn scope_subset_error(scope: &str) -> String {
    format!("scope `{scope}` is outside the active scopeAllowlist")
}

fn validate_scope_subset(scopes: &[String], allowlist: &[String]) -> Result<(), Response> {
    scopes
        .iter()
        .find(|scope| !allowlist.iter().any(|allowed| allowed == *scope))
        .map_or(Ok(()), |scope| {
            Err(invalid_client_metadata_response(scope_subset_error(scope)))
        })
}

fn parse_declared_scope(scope: &str) -> Result<Vec<String>, Response> {
    crate::oauth_scope::parse_scope_string(scope).map_err(invalid_scope_response)
}

pub(super) fn validate_registration_scope_or_response(
    meta: &ClientRegistration,
    scope_allowlist: &[String],
) -> Result<(), Response> {
    let Some(scope) = meta.scope.as_deref() else {
        return Ok(());
    };
    let scopes = parse_declared_scope(scope)?;
    validate_scope_subset(&scopes, scope_allowlist)
}

pub(super) fn resolve_registration_allowed_scopes(
    meta: &ClientRegistration,
    existing: Option<&RegisteredClient>,
    scope_allowlist: &[String],
) -> Result<Vec<String>, Response> {
    let scopes = match meta.scope.as_deref() {
        Some(scope) => parse_declared_scope(scope)?,
        None => existing.map_or_else(
            || scope_allowlist.to_vec(),
            |client| client.allowed_scopes.clone(),
        ),
    };
    validate_scope_subset(&scopes, scope_allowlist)?;
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(scope: Option<&str>) -> ClientRegistration {
        ClientRegistration {
            scope: scope.map(str::to_string),
            ..ClientRegistration::default()
        }
    }

    fn client(scopes: &[&str]) -> RegisteredClient {
        RegisteredClient {
            client_id: "client-id".to_string(),
            client_secret: None,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            token_endpoint_auth_method: "none".to_string(),
            jwks_pem: None,
            inline_jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            allowed_scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
            allowed_grant_types: vec!["authorization_code".to_string()],
            registration_access_token: Some("rat".to_string()),
            client_id_issued_at: Some(1),
        }
    }

    #[test]
    fn explicit_scope_must_be_subset_of_runtime_allowlist() {
        let allowlist = vec!["openid".to_string(), "profile".to_string()];

        assert_eq!(
            resolve_registration_allowed_scopes(
                &registration(Some("openid profile")),
                None,
                &allowlist
            )
            .expect("scope subset"),
            vec!["openid".to_string(), "profile".to_string()]
        );
        assert!(resolve_registration_allowed_scopes(
            &registration(Some("openid email")),
            None,
            &allowlist
        )
        .is_err());
    }

    #[test]
    fn missing_scope_defaults_to_allowlist_for_create_and_preserves_existing_for_update() {
        let allowlist = vec!["openid".to_string(), "profile".to_string()];
        assert_eq!(
            resolve_registration_allowed_scopes(&registration(None), None, &allowlist)
                .expect("default scopes"),
            allowlist
        );
        assert_eq!(
            resolve_registration_allowed_scopes(
                &registration(None),
                Some(&client(&["openid"])),
                &["openid".to_string(), "profile".to_string()],
            )
            .expect("preserved scopes"),
            vec!["openid".to_string()]
        );
    }
}
