use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::kms::KeyManager;
use crate::metadata::{
    advertised_client_auth_methods, advertised_request_object_signing_algs,
    alg_allowed_with_promoted_rsa, AuthorizationServerMetadata, MetadataRuntimeConfig,
    ProtectedResourceMetadata,
};
use crate::oidc::OidcDiscovery;

use super::{json_error_with_iss, no_cache_json_error_with_iss, AppState};

fn advertised_client_jwt_algs(state: &AppState) -> Option<Vec<String>> {
    let mut algs = state
        .dcr_allowed_algs
        .iter()
        .filter(|name| alg_allowed_with_promoted_rsa(name, state.cfg.crypto_profile))
        .cloned()
        .collect::<Vec<_>>();
    algs.sort();
    (!algs.is_empty()).then_some(algs)
}

fn advertised_client_auth_methods_and_algs(state: &AppState) -> (Vec<String>, Option<Vec<String>>) {
    let client_jwt_algs = state
        .cfg
        .grant_runtime()
        .private_key_jwt_enabled()
        .then(|| advertised_client_jwt_algs(state))
        .flatten();
    let methods = advertised_client_auth_methods(client_jwt_algs.is_some());
    (methods, client_jwt_algs)
}

pub(in crate::web) fn metadata_runtime_config(state: &AppState) -> MetadataRuntimeConfig {
    let grants = state.cfg.grant_runtime();
    MetadataRuntimeConfig {
        crypto_profile: state.cfg.crypto_profile,
        mtls_enabled: state.cfg.mtls_enabled,
        mtls_base_url: state.cfg.mtls_base_url.clone(),
        mtls_alias_par: state.cfg.mtls_alias_par,
        dcr_enabled: state.dcr_enabled,
        enable_private_key_jwt: grants.private_key_jwt_enabled(),
        client_jwt_algs: advertised_client_jwt_algs(state)
            .map_or_else(Vec::new, std::convert::identity),
        grant_types_supported: state.cfg.allowed_grant_types.clone(),
        enable_device_authz: grants.device_authorization_enabled(),
        require_pushed_authorization_requests: state.cfg.require_pushed_authorization_requests,
        authorization_details_types_supported: state
            .cfg
            .authorization_details_types_supported
            .clone(),
    }
}

fn public_jwt_signing_alg(state: &AppState) -> Option<String> {
    state
        .keys
        .access_token
        .jwt_signing_public_jwk()
        .map(|_| state.keys.access_token.jwt_signing_alg().to_string())
}

pub(super) fn jwt_introspection_key_manager(state: &AppState) -> &dyn KeyManager {
    state
        .keys
        .jwt_introspection
        .as_deref()
        .unwrap_or(state.keys.access_token.as_ref())
}

fn advertised_jwt_signing_alg(state: &AppState) -> Option<String> {
    state
        .cfg
        .jwt_runtime()
        .access_tokens_enabled()
        .then(|| public_jwt_signing_alg(state))
        .flatten()
}

fn advertises_public_jwt_signing(state: &AppState) -> bool {
    advertised_jwt_signing_alg(state).is_some()
}

fn apply_device_authorization_metadata(meta: &mut AuthorizationServerMetadata, state: &AppState) {
    if state.cfg.grant_runtime().device_authorization_enabled() {
        meta.device_authorization_endpoint = Some(format!(
            "{}/device_authorization",
            state.issuer.trim_end_matches('/')
        ));
    } else {
        meta.device_authorization_endpoint = None;
    }
}

pub(in crate::web) fn authorization_server_metadata_for_state(
    state: &AppState,
) -> Result<AuthorizationServerMetadata, crate::config::ConfigError> {
    let runtime_metadata = metadata_runtime_config(state);
    let mut meta = AuthorizationServerMetadata::try_new_secure_with_runtime_config(
        &state.issuer,
        &runtime_metadata,
    )?;
    apply_device_authorization_metadata(&mut meta, state);
    if state.oidc.config.is_none() {
        meta.scopes_supported = None;
    }
    meta.aegaeon_access_token_formats_supported = if advertises_public_jwt_signing(state) {
        Some(vec!["at+jwt".to_string()])
    } else {
        None
    };
    if let Some(alg) = advertised_jwt_signing_alg(state) {
        meta.access_token_signing_alg_values_supported = Some(vec![alg]);
    } else {
        meta.access_token_signing_alg_values_supported = None;
    }
    if state.cfg.jwt_runtime().introspection_enabled() {
        let key_manager = jwt_introspection_key_manager(state);
        meta.introspection_signing_alg_values_supported = key_manager
            .jwt_signing_public_jwk()
            .map(|_| vec![key_manager.jwt_signing_alg().to_string()]);
    }
    let (methods, client_jwt_algs) = advertised_client_auth_methods_and_algs(state);
    meta.token_endpoint_auth_methods_supported = Some(methods.clone());
    meta.revocation_endpoint_auth_methods_supported = Some(methods.clone());
    meta.introspection_endpoint_auth_methods_supported = Some(methods);

    if let Some(algs) = client_jwt_algs {
        meta.token_endpoint_auth_signing_alg_values_supported = Some(algs.clone());
        meta.revocation_endpoint_auth_signing_alg_values_supported = Some(algs.clone());
        meta.introspection_endpoint_auth_signing_alg_values_supported = Some(algs);
        if state.dcr_require_client_jwt_kid {
            meta.client_jwt_kid_required = Some(true);
        }
    }
    if !state.cfg.acr_values_supported.is_empty() {
        meta.acr_values_supported = Some(state.cfg.acr_values_supported.clone());
    }
    Ok(meta)
}

pub(in crate::web) fn oidc_discovery_for_state(state: &AppState) -> Option<OidcDiscovery> {
    let cfg = state.oidc.config.as_deref()?;
    let runtime_metadata = metadata_runtime_config(state);
    let mut doc =
        OidcDiscovery::new_with_runtime_config(&cfg.issuer, &cfg.issuer, &runtime_metadata);
    doc.aegaeon_access_token_formats_supported = if advertises_public_jwt_signing(state) {
        Some(vec!["at+jwt".to_string()])
    } else {
        None
    };
    if !state.cfg.acr_values_supported.is_empty() {
        doc.acr_values_supported = Some(state.cfg.acr_values_supported.clone());
    }
    if !cfg.userinfo_enabled {
        doc.userinfo_endpoint = None;
    }
    if cfg.logout_enabled {
        let issuer = cfg.issuer.trim_end_matches('/');
        doc.end_session_endpoint = Some(format!("{issuer}/logout"));
    }

    let (methods, client_jwt_algs) = advertised_client_auth_methods_and_algs(state);
    doc.token_endpoint_auth_methods_supported = Some(methods.clone());
    doc.revocation_endpoint_auth_methods_supported = Some(methods.clone());
    doc.introspection_endpoint_auth_methods_supported = Some(methods);

    if let Some(algs) = client_jwt_algs {
        doc.token_endpoint_auth_signing_alg_values_supported = Some(algs.clone());
        doc.revocation_endpoint_auth_signing_alg_values_supported = Some(algs.clone());
        doc.introspection_endpoint_auth_signing_alg_values_supported = Some(algs);
    }

    doc.request_object_signing_alg_values_supported = Some(advertised_request_object_signing_algs(
        state.cfg.crypto_profile,
    ));
    if cfg.request_object_encryption_key.is_some() {
        doc.request_object_encryption_alg_values_supported = Some(vec!["RSA-OAEP".to_string()]);
        doc.request_object_encryption_enc_values_supported = Some(vec!["A256GCM".to_string()]);
    }

    Some(doc)
}

pub(super) async fn well_known_oauth_authorization_server(
    State(state): State<AppState>,
) -> Response {
    let meta = match authorization_server_metadata_for_state(&state) {
        Ok(meta) => meta,
        Err(err) => {
            tracing::error!(error = %err, "failed to build OAuth authorization server metadata");
            return no_cache_json_error_with_iss(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("failed to build authorization server metadata"),
                state.issuer.as_str(),
            );
        }
    };

    Json(meta).into_response()
}

/// RFC 9728 — Protected Resource Metadata endpoint.
/// Publishes the capabilities of the /resource endpoint so that clients can
/// discover scopes, sender-constraint requirements, and the authorization
/// server(s) that can issue tokens for this resource.
pub(super) async fn well_known_oauth_protected_resource(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let mut meta =
        ProtectedResourceMetadata::for_issuer_with_mtls(&state.issuer, state.cfg.mtls_enabled);

    if !state.cfg.authorization_details_types_supported.is_empty() {
        meta.authorization_details_types_supported =
            Some(state.cfg.authorization_details_types_supported.clone());
    }

    Json(meta)
}

pub(super) async fn well_known_openid_configuration(State(state): State<AppState>) -> Response {
    let Some(cfg) = state.oidc.config.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !cfg.discovery_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Some(doc) = oidc_discovery_for_state(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    Json(doc).into_response()
}

pub(super) async fn jwks(State(state): State<AppState>) -> Response {
    let mut keys = match state.oidc.config.as_deref() {
        Some(cfg) => match cfg
            .jwks()
            .keys
            .into_iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(keys) => keys,
            Err(err) => {
                tracing::error!(error = %err, "failed to serialize OIDC JWKS");
                return json_error_with_iss(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    Some("failed to build JWKS response"),
                    state.issuer.as_str(),
                );
            }
        },
        None => Vec::new(),
    };

    for jwt_jwk in state
        .keys
        .access_token
        .jwt_signing_public_jwks()
        .into_iter()
        .chain(
            state
                .keys
                .jwt_introspection
                .iter()
                .flat_map(|manager| manager.jwt_signing_public_jwks()),
        )
    {
        let jwt_kid = jwt_jwk.get("kid").and_then(Value::as_str);
        if jwt_kid.is_none_or(|kid| {
            !keys
                .iter()
                .any(|jwk| jwk.get("kid").and_then(Value::as_str) == Some(kid))
        }) {
            keys.push(jwt_jwk);
        }
    }

    Json(json!({ "keys": keys })).into_response()
}
