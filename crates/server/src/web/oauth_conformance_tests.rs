use super::token_form::token_form_from_params;
use super::token_sender_binding::{dpop_binding_from_request, dpop_error_response};
use crate::middleware::dpop::DpopEndpointRole;
use crate::middleware::DpopMiddleware;
use axum::{
    body::to_bytes,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::Value;

mod sender_contract;
mod transport_contract;

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn error(response: Response, status: StatusCode, code: &str) -> TestResult {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(body["error"], code);
    assert!(body.get("access_token").is_none());
    Ok(())
}

#[tokio::test]
async fn rar_constraints_are_never_ignored_by_any_token_grant() -> TestResult {
    for grant in [
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:token-exchange",
        "urn:ietf:params:oauth:grant-type:device_code",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
    ] {
        for details in [
            "[]",
            "null",
            "{}",
            "not-json",
            " ",
            r#"[{"type":"payment","amount":"1"}]"#,
        ] {
            let params = vec![
                ("grant_type".into(), grant.into()),
                ("authorization_details".into(), details.into()),
            ];
            let response = token_form_from_params(&params, "https://issuer.example")
                .err()
                .ok_or("authorization_details was ignored")?;
            error(
                response,
                StatusCode::BAD_REQUEST,
                "invalid_authorization_details",
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn rar_duplicates_are_invalid_even_when_empty() -> TestResult {
    let params = vec![
        ("grant_type".into(), "client_credentials".into()),
        ("authorization_details".into(), "".into()),
        ("authorization_details".into(), "".into()),
    ];
    let response = token_form_from_params(&params, "https://issuer.example")
        .err()
        .ok_or("duplicate accepted")?;
    error(response, StatusCode::BAD_REQUEST, "invalid_request").await
}

#[test]
fn empty_rar_and_unknown_extensions_preserve_oauth_compatibility() -> TestResult {
    let params = vec![
        ("grant_type".into(), "client_credentials".into()),
        ("authorization_details".into(), "".into()),
        ("unknown_extension".into(), "value".into()),
    ];
    assert!(token_form_from_params(&params, "https://issuer.example").is_ok());
    Ok(())
}

#[tokio::test]
async fn resource_malformed_proof_has_dpop_proof_challenge() -> TestResult {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "DPoP token".parse()?);
    headers.insert("dpop", "not-a-jwt".parse()?);
    let response = dpop_binding_from_request(
        &DpopMiddleware::new_process_local_for_tests(),
        DpopEndpointRole::ResourceServer,
        &http::Method::GET,
        &"/resource".parse()?,
        &headers,
    )
    .err()
    .ok_or("malformed proof accepted")?;
    let response = dpop_error_response(
        "https://issuer.example",
        DpopEndpointRole::ResourceServer,
        response,
    );
    assert_eq!(
        response.headers()["www-authenticate"],
        "DPoP realm=\"aegaeon\", error=\"invalid_dpop_proof\""
    );
    error(response, StatusCode::UNAUTHORIZED, "invalid_dpop_proof").await
}

#[tokio::test]
async fn dpop_roles_have_distinct_errors_and_nonce_challenges() -> TestResult {
    use crate::middleware::DpopError;
    for role in [
        DpopEndpointRole::AuthorizationServer,
        DpopEndpointRole::ResourceServer,
    ] {
        let expected_status = if role == DpopEndpointRole::AuthorizationServer {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::UNAUTHORIZED
        };
        for failure in [
            DpopError::InvalidProof,
            DpopError::Replay,
            DpopError::MissingProof,
        ] {
            let response = dpop_error_response("https://issuer.example", role, failure);
            assert_eq!(
                response.headers().contains_key("www-authenticate"),
                role == DpopEndpointRole::ResourceServer
            );
            error(response, expected_status, "invalid_dpop_proof").await?;
        }
        let response = dpop_error_response(
            "https://issuer.example",
            role,
            DpopError::UseDpopNonce("fresh-nonce".into()),
        );
        assert_eq!(response.headers()["dpop-nonce"], "fresh-nonce");
        if role == DpopEndpointRole::ResourceServer {
            assert_eq!(
                response.headers()["www-authenticate"],
                "DPoP realm=\"aegaeon\", error=\"use_dpop_nonce\""
            );
        }
        error(response, expected_status, "use_dpop_nonce").await?;
        let response = dpop_error_response(
            "https://issuer.example",
            role,
            DpopError::BackendUnavailable("private connection detail".into()),
        );
        assert!(!response.headers().contains_key("www-authenticate"));
        error(
            response,
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
        )
        .await?;
    }
    Ok(())
}

#[test]
fn dpop_nonce_roles_are_not_interchangeable() -> TestResult {
    let store =
        crate::middleware::DpopNonceStore::new_process_local(std::time::Duration::from_secs(300));
    for role in [
        DpopEndpointRole::AuthorizationServer,
        DpopEndpointRole::ResourceServer,
    ] {
        let nonce = store
            .try_get_current_nonce_for(role)
            .map_err(|e| format!("{e:?}"))?;
        assert!(store
            .try_validate_nonce_for(role, &nonce)
            .map_err(|e| format!("{e:?}"))?);
        let other = if role == DpopEndpointRole::AuthorizationServer {
            DpopEndpointRole::ResourceServer
        } else {
            DpopEndpointRole::AuthorizationServer
        };
        assert!(!store
            .try_validate_nonce_for(other, &nonce)
            .map_err(|e| format!("{e:?}"))?);
    }
    Ok(())
}

#[test]
fn certificate_token_policy_does_not_require_browser_certificates() {
    let policy = crate::policy::SecurityPolicy::default()
        .with_sender_constraint(crate::policy::SenderConstraint::Mtls);
    let mut transport = crate::config::TransportSecurityConfig::default();
    transport.apply_security_policy(&policy);
    assert!(transport.require_tls_proxy);
    assert!(!transport.require_proxy_mtls);
    transport.require_proxy_mtls = true;
    transport.apply_security_policy(&policy);
    assert!(
        transport.require_proxy_mtls,
        "explicit ingress certificate requirements remain effective"
    );
}

#[test]
fn standard_certificate_registration_flag_is_not_generic_sender_binding() -> TestResult {
    let registration = crate::dcr::parse_client_registration(
        br#"{"tls_client_certificate_bound_access_tokens":true}"#,
    )
    .map_err(|e| format!("{e:?}"))?;
    assert_eq!(registration.require_mtls, Some(true));
    assert_eq!(registration.require_sender_constrained_tokens, None);
    Ok(())
}

#[test]
fn runtime_rejects_rar_type_names_without_semantic_handlers() {
    let mut policy = crate::management::types::PolicyDocument::default();
    assert!(crate::config::validate_management_policy_for_runtime(&policy).is_ok());
    policy.authorization_details_types_supported = vec!["payment_initiation".into()];
    assert!(crate::config::validate_management_policy_for_runtime(&policy).is_err());
}

#[test]
fn certificate_context_requires_trusted_https_provenance() -> TestResult {
    use crate::middleware::tls::{TransportRejectionKind, TransportSecurity};
    let cfg = crate::config::TransportSecurityConfig {
        require_tls_proxy: true,
        trusted_proxies: vec!["127.0.0.3/32".parse()?],
        ..Default::default()
    };
    let transport = TransportSecurity::new(cfg);
    let trusted = Some("127.0.0.3:12345".parse()?);
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-proto", "https".parse()?);
    let fingerprint = format!("SHA256:{}", "AB".repeat(32));
    headers.insert("x-forwarded-client-cert", fingerprint.parse()?);
    let cert = transport
        .verified_client_certificate(trusted, &headers)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("verified certificate")?;
    assert_eq!(cert.fingerprint(), fingerprint);
    assert!(matches!(
        transport.verified_client_certificate(Some("127.0.0.2:12345".parse()?), &headers),
        Err(TransportRejectionKind::UntrustedProxy)
    ));
    headers.append("x-forwarded-client-cert", fingerprint.parse()?);
    assert!(transport
        .verified_client_certificate(trusted, &headers)
        .is_err());
    headers.remove("x-forwarded-client-cert");
    assert!(transport
        .verified_client_certificate(trusted, &headers)
        .map_err(|e| format!("{e:?}"))?
        .is_none());
    headers.insert("x-forwarded-proto", "http".parse()?);
    assert!(transport
        .verified_client_certificate(trusted, &headers)
        .is_err());
    Ok(())
}

#[test]
fn resource_checks_committed_binding_in_mixed_profile_environments() -> TestResult {
    use crate::authcode::types::{BearerTokenMeta, BearerTokenMetaInput, SenderBinding};
    use crate::authcode::{TokenPolicyContext, TokenValidator};
    use crate::policy::{SecurityPolicy, SenderConstraint};
    let now = std::time::SystemTime::now();
    for default in [SenderConstraint::DPoP, SenderConstraint::Mtls] {
        for binding in [
            SenderBinding::DPoP {
                jkt: "test-key".into(),
            },
            SenderBinding::Mtls {
                fingerprint: "test-cert".into(),
            },
        ] {
            let meta = BearerTokenMeta::new(BearerTokenMetaInput {
                token_id: "access".into(),
                client_id: "client".into(),
                user_id: "user".into(),
                granted_scopes: vec!["read".into()],
                audience: "api".into(),
                sender_binding: Some(binding.clone()),
                authorization_details: None,
                auth_time_epoch_secs: None,
                acr: None,
                issued_at: now,
                expires_at: now + std::time::Duration::from_secs(60),
                refresh_parent: None,
            });
            let validator = TokenValidator::with_policy(
                crate::authcode::TokenStore::new_process_local_for_tests(),
                std::sync::Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?),
                SecurityPolicy::default().with_sender_constraint(default),
            );
            for (jkt, cert, valid) in [
                (Some("test-key"), Some("test-cert"), true),
                (None, None, false),
                (Some("wrong-key"), Some("wrong-cert"), false),
            ] {
                let context = TokenPolicyContext {
                    requested_scopes: &["read"],
                    resource_audience: Some("api"),
                    sender_dpop_jkt: jkt,
                    sender_mtls_fingerprint: cert,
                };
                assert_eq!(validator.enforce_with_meta(&meta, context).is_ok(), valid);
            }
        }
    }
    assert_eq!(
        crate::oauth_profile::merge_sender_constraints(
            SenderConstraint::Mtls,
            SenderConstraint::DPoP
        ),
        SenderConstraint::DPoP
    );
    assert_eq!(
        crate::oauth_profile::merge_sender_constraints(
            SenderConstraint::DPoP,
            SenderConstraint::None
        ),
        SenderConstraint::DPoP
    );
    Ok(())
}

#[test]
fn resource_dpop_scheme_requires_a_proof() -> TestResult {
    let middleware = DpopMiddleware::new_process_local_for_tests();
    let mut headers = HeaderMap::new();
    for authorization in [
        "DPoP opaque-token",
        "DPoP\topaque-token",
        " dpop  opaque-token",
    ] {
        headers.insert("authorization", authorization.parse()?);
        assert!(matches!(
            dpop_binding_from_request(
                &middleware,
                DpopEndpointRole::ResourceServer,
                &http::Method::GET,
                &"/resource".parse()?,
                &headers
            ),
            Err(crate::middleware::DpopError::MissingProof)
        ));
    }
    headers.insert("authorization", "Bearer opaque-token".parse()?);
    assert!(dpop_binding_from_request(
        &middleware,
        DpopEndpointRole::ResourceServer,
        &http::Method::GET,
        &"/resource".parse()?,
        &headers
    )
    .map_err(|e| format!("{e:?}"))?
    .is_none());
    Ok(())
}
