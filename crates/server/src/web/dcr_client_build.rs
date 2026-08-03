use super::dcr_response::invalid_client_metadata_response;
use super::dcr_scope::resolve_registration_allowed_scopes;
use axum::response::Response;

use crate::dcr::ClientRegistration;

fn generate_secret() -> String {
    aegaeon_crypto::rand::random_base64url(32)
}

fn default_registration_grant_types() -> Vec<String> {
    vec![
        "authorization_code".to_string(),
        "refresh_token".to_string(),
    ]
}

fn sanitized_backchannel_logout_uri(
    value: Option<&str>,
    fallback: Option<&String>,
) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| fallback.cloned())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ExistingDcrClientSecret {
    None,
    Plaintext(String),
    PresentWithoutPlaintext,
}

#[derive(Clone, Debug)]
pub(super) struct BuiltDcrClient {
    pub(super) client: crate::client_registry::RegisteredClient,
    pub(super) generated_client_secret: Option<String>,
}

pub(super) struct DcrClientBuildInput<'a> {
    pub(super) meta: &'a ClientRegistration,
    pub(super) client_id: String,
    pub(super) registration_access_token: String,
    pub(super) client_id_issued_at: Option<u64>,
    pub(super) existing: Option<&'a crate::client_registry::RegisteredClient>,
    pub(super) existing_secret: ExistingDcrClientSecret,
    pub(super) require_client_jwt_kid: bool,
    pub(super) scope_allowlist: &'a [String],
}

pub(super) fn build_registered_client_from_metadata(
    meta: &ClientRegistration,
    client_id: String,
    registration_access_token: String,
    client_id_issued_at: Option<u64>,
    existing: Option<&crate::client_registry::RegisteredClient>,
    require_client_jwt_kid: bool,
    scope_allowlist: &[String],
) -> Result<crate::client_registry::RegisteredClient, Response> {
    build_registered_client_from_metadata_with_secret_state(DcrClientBuildInput {
        meta,
        client_id,
        registration_access_token,
        client_id_issued_at,
        existing,
        existing_secret: existing
            .and_then(|client| client.client_secret.clone())
            .map_or(
                ExistingDcrClientSecret::None,
                ExistingDcrClientSecret::Plaintext,
            ),
        require_client_jwt_kid,
        scope_allowlist,
    })
    .map(|built| built.client)
}

pub(super) fn build_registered_client_from_metadata_with_secret_state(
    input: DcrClientBuildInput<'_>,
) -> Result<BuiltDcrClient, Response> {
    let DcrClientBuildInput {
        meta,
        client_id,
        registration_access_token,
        client_id_issued_at,
        existing,
        existing_secret,
        require_client_jwt_kid,
        scope_allowlist,
    } = input;
    let method = canonical_token_endpoint_auth_method(
        meta.token_endpoint_auth_method
            .as_deref()
            .unwrap_or_else(|| {
                existing.map_or("client_secret_basic", |client| {
                    client.token_endpoint_auth_method.as_str()
                })
            }),
    );
    let (secret, generated_client_secret) = if client_auth_method_uses_secret(&method) {
        match existing_secret {
            ExistingDcrClientSecret::Plaintext(secret) => (Some(secret), None),
            ExistingDcrClientSecret::PresentWithoutPlaintext => (None, None),
            ExistingDcrClientSecret::None => {
                let secret = generate_secret();
                (Some(secret.clone()), Some(secret))
            }
        }
    } else {
        (None, None)
    };
    let redirect_uris = meta
        .redirect_uris
        .clone()
        .unwrap_or_else(|| existing.map_or_else(Vec::new, |client| client.redirect_uris.clone()));
    let post_logout_redirect_uris = meta.post_logout_redirect_uris.clone().unwrap_or_else(|| {
        existing.map_or_else(Vec::new, |client| client.post_logout_redirect_uris.clone())
    });
    let backchannel_logout_uri = sanitized_backchannel_logout_uri(
        meta.backchannel_logout_uri.as_deref(),
        existing.and_then(|client| client.backchannel_logout_uri.as_ref()),
    );
    let backchannel_logout_session_required =
        meta.backchannel_logout_session_required.unwrap_or_else(|| {
            existing.is_some_and(|client| client.backchannel_logout_session_required)
        });
    let allowed_grant_types = meta.grant_types.clone().unwrap_or_else(|| {
        existing.map_or_else(default_registration_grant_types, |client| {
            client.allowed_grant_types.clone()
        })
    });
    let inline_jwks = meta
        .jwks
        .clone()
        .map(|value| {
            crate::client_registry::RegisteredClientJwks::from_value(value, require_client_jwt_kid)
                .map_err(invalid_client_metadata_response)
        })
        .transpose()?;
    let token_endpoint_auth_signing_alg = (method == "private_key_jwt")
        .then(|| {
            meta.token_endpoint_auth_signing_alg
                .as_deref()
                .map(|alg| alg.trim().to_ascii_uppercase())
                .or_else(|| {
                    existing.and_then(|client| client.token_endpoint_auth_signing_alg.clone())
                })
        })
        .flatten();
    let allowed_scopes = resolve_registration_allowed_scopes(meta, existing, scope_allowlist)?;

    Ok(BuiltDcrClient {
        client: crate::client_registry::RegisteredClient {
            client_id,
            client_secret: secret,
            redirect_uris,
            post_logout_redirect_uris,
            backchannel_logout_uri,
            backchannel_logout_session_required,
            token_endpoint_auth_method: method,
            jwks_pem: existing.and_then(|client| client.jwks_pem.clone()),
            inline_jwks,
            jwks_uri: meta.jwks_uri.clone(),
            token_endpoint_auth_signing_alg,
            allowed_scopes,
            allowed_grant_types,
            registration_access_token: Some(registration_access_token),
            client_id_issued_at,
        },
        generated_client_secret,
    })
}

fn canonical_token_endpoint_auth_method(method: &str) -> String {
    method.trim().to_ascii_lowercase()
}

fn client_auth_method_uses_secret(method: &str) -> bool {
    let method = method.trim();
    method.eq_ignore_ascii_case("client_secret_basic")
        || method.eq_ignore_ascii_case("client_secret_post")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dcr_persistence::DcrClientSecretChange;
    use crate::web::dcr_runtime::dcr_database_secret_change;

    type TestResult = Result<(), String>;

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

    fn scope_allowlist() -> Vec<String> {
        vec!["read".to_string(), "write".to_string()]
    }

    #[test]
    fn dcr_database_update_preserves_existing_secret_without_plaintext() -> TestResult {
        let meta = ClientRegistration {
            redirect_uris: Some(vec!["https://new.example.com/callback".to_string()]),
            token_endpoint_auth_method: Some("client_secret_basic".to_string()),
            ..ClientRegistration::default()
        };
        let existing = existing_client(vec!["authorization_code".to_string()]);
        let scope_allowlist = scope_allowlist();

        let built = build_registered_client_from_metadata_with_secret_state(DcrClientBuildInput {
            meta: &meta,
            client_id: existing.client_id.clone(),
            registration_access_token: "new-rat".to_string(),
            client_id_issued_at: existing.client_id_issued_at,
            existing: Some(&existing),
            existing_secret: ExistingDcrClientSecret::PresentWithoutPlaintext,
            require_client_jwt_kid: false,
            scope_allowlist: &scope_allowlist,
        })
        .map_err(|response| format!("registered client response status: {}", response.status()))?;

        assert!(built.client.client_secret.is_none());
        assert!(built.generated_client_secret.is_none());
        assert_eq!(built.client.allowed_scopes, vec!["read".to_string()]);
        assert_eq!(
            dcr_database_secret_change(
                &built.client.token_endpoint_auth_method,
                built.generated_client_secret
            ),
            DcrClientSecretChange::Preserve
        );
        Ok(())
    }

    #[test]
    fn dcr_database_update_generates_secret_for_new_secret_auth_client() -> TestResult {
        let meta = ClientRegistration {
            redirect_uris: Some(vec!["https://new.example.com/callback".to_string()]),
            token_endpoint_auth_method: Some("client_secret_post".to_string()),
            ..ClientRegistration::default()
        };
        let scope_allowlist = scope_allowlist();

        let built = build_registered_client_from_metadata_with_secret_state(DcrClientBuildInput {
            meta: &meta,
            client_id: "client-id".to_string(),
            registration_access_token: "new-rat".to_string(),
            client_id_issued_at: Some(1),
            existing: None,
            existing_secret: ExistingDcrClientSecret::None,
            require_client_jwt_kid: false,
            scope_allowlist: &scope_allowlist,
        })
        .map_err(|response| format!("registered client response status: {}", response.status()))?;

        assert!(built.client.client_secret.is_some());
        assert_eq!(
            built.client.allowed_scopes,
            vec!["read".to_string(), "write".to_string()]
        );
        assert!(matches!(
            dcr_database_secret_change(
                &built.client.token_endpoint_auth_method,
                built.generated_client_secret
            ),
            DcrClientSecretChange::ReplaceWithPlaintext(secret) if !secret.is_empty()
        ));
        Ok(())
    }

    #[test]
    fn dcr_scope_metadata_replaces_default_scope_allowlist() -> TestResult {
        let meta = ClientRegistration {
            scope: Some("write".to_string()),
            ..ClientRegistration::default()
        };
        let scope_allowlist = scope_allowlist();
        let built = build_registered_client_from_metadata_with_secret_state(DcrClientBuildInput {
            meta: &meta,
            client_id: "client-id".to_string(),
            registration_access_token: "new-rat".to_string(),
            client_id_issued_at: Some(1),
            existing: None,
            existing_secret: ExistingDcrClientSecret::None,
            require_client_jwt_kid: false,
            scope_allowlist: &scope_allowlist,
        })
        .map_err(|response| format!("registered client response status: {}", response.status()))?;

        assert_eq!(built.client.allowed_scopes, vec!["write".to_string()]);
        Ok(())
    }

    #[test]
    fn dcr_scope_metadata_must_be_inside_scope_allowlist() -> TestResult {
        let meta = ClientRegistration {
            scope: Some("admin".to_string()),
            ..ClientRegistration::default()
        };
        let scope_allowlist = scope_allowlist();

        let response =
            build_registered_client_from_metadata_with_secret_state(DcrClientBuildInput {
                meta: &meta,
                client_id: "client-id".to_string(),
                registration_access_token: "new-rat".to_string(),
                client_id_issued_at: Some(1),
                existing: None,
                existing_secret: ExistingDcrClientSecret::None,
                require_client_jwt_kid: false,
                scope_allowlist: &scope_allowlist,
            })
            .expect_err("disallowed scope must be rejected");

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        Ok(())
    }
}
