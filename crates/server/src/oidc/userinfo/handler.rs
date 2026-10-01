use axum::{
    extract::Extension,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use super::{Error, UserinfoEndpoint};
use crate::middleware::tls::VerifiedClientCertificate;
use crate::middleware::DpopBinding;
use crate::util;

/// Axum handler for userinfo endpoint
pub async fn userinfo_handler(
    headers: HeaderMap,
    Extension(endpoint): Extension<Arc<UserinfoEndpoint>>,
    binding: Option<Extension<DpopBinding>>,
    certificate: Option<Extension<VerifiedClientCertificate>>,
) -> impl IntoResponse {
    let auth_header = match util::single_header_str(&headers, header::AUTHORIZATION.as_str()) {
        Ok(Some(value)) => value,
        Ok(None) => "",
        Err(err) => {
            let description = err.description("Authorization");
            return userinfo_json_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(&description),
                true,
            );
        }
    };
    // Headers alone are not certificate evidence. Middleware must establish
    // proxy provenance and provide this unforgeable transport context.
    let mtls_fingerprint = certificate
        .as_ref()
        .map(|Extension(cert)| cert.fingerprint());

    let binding_ref = binding.as_ref().map(|Extension(binding)| binding);

    match endpoint
        .handle(auth_header, binding_ref, mtls_fingerprint)
        .await
    {
        Ok(response) => response.into_response(),
        Err(Error::InvalidToken) => {
            userinfo_json_error_response(StatusCode::UNAUTHORIZED, "invalid_token", None, true)
        }
        Err(Error::InsufficientScope) => {
            userinfo_json_error_response(StatusCode::FORBIDDEN, "insufficient_scope", None, true)
        }
        Err(Error::InvalidRequest(message)) => userinfo_json_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(message.as_str()),
            true,
        ),
        Err(Error::ServerError(_)) => userinfo_json_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("userinfo endpoint failed internally"),
            false,
        ),
    }
}

fn userinfo_json_error_response(
    status: StatusCode,
    error: &'static str,
    description: Option<&str>,
    authenticate: bool,
) -> Response {
    let body = crate::oauth_error::json_body(error, description);
    let error = crate::oauth_error::code(error);
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if authenticate {
        let value = format!("Bearer realm=\"aegaeon\", error=\"{error}\"");
        if let Ok(value) = HeaderValue::from_str(&value) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn oauth_error_encoding_test_only_userinfo_boundary_and_exported_handler(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for description in [None, Some(""), Some("bad\"\\é")] {
            let response = userinfo_json_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                description,
                true,
            );
            assert_eq!(
                response.headers()[header::WWW_AUTHENTICATE],
                "Bearer realm=\"aegaeon\", error=\"invalid_request\""
            );
            let body: serde_json::Value =
                serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await?)?;
            if description == Some("bad\"\\é") {
                assert_eq!(body["error_description"], "bad???");
            } else {
                assert!(body.get("error_description").is_none());
            }
        }
        let endpoint = UserinfoEndpoint::with_user_provider_for_tests(
            crate::authcode::TokenValidator::new(
                crate::authcode::TokenStore::new_process_local_for_tests(),
                Arc::new(crate::kms::InMemoryKeyManager::new()),
            ),
            Arc::new(crate::oidc::userinfo::InMemoryUserProvider::new()),
        );
        let response = crate::oidc::userinfo::userinfo_handler(
            HeaderMap::new(),
            Extension(Arc::new(endpoint)),
            None,
            None,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "invalid_request");
        assert_eq!(body["error_description"], "Invalid authorization header");
        Ok(())
    }
}
