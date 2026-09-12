use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, Uri},
    response::Response,
};

use crate::authcode::types::{CnfClaim, RefreshToken, SenderBinding};
use crate::middleware::tls::{mtls_fingerprint_to_x5t_s256, normalize_forwarded_client_cert};
use crate::middleware::{DpopBinding, DpopError, DpopMiddleware};
use crate::policy::SenderConstraint;
use crate::util;

use super::oauth_errors::{
    apply_oauth_authenticate_header, authorization_header, dpop_header,
    forwarded_client_cert_header, no_cache_json_error_with_iss, token_header_error,
};
use super::token_response::token_error_response;
use super::{AppState, X_FORWARDED_CLIENT_CERT_HEADER};
use crate::middleware::dpop::DpopEndpointRole;

/// Validation retains its error category until the endpoint renders its role.
pub(super) fn dpop_binding_from_request(
    dpop: &DpopMiddleware,
    role: DpopEndpointRole,
    method: &http::Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Option<DpopBinding>, DpopError> {
    let auth = authorization_header(headers).map_err(|_| DpopError::InvalidProof)?;
    let proof = dpop_header(headers).map_err(|_| DpopError::InvalidProof)?;
    let Some(proof) = proof else {
        if role == DpopEndpointRole::ResourceServer
            && auth
                .and_then(|value| value.split_whitespace().next())
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("DPoP"))
        {
            return Err(DpopError::MissingProof);
        }
        return Ok(None);
    };
    dpop.verify_components_for(role, method, uri, proof, auth)
        .map(Some)
}

/// RFC 9449 §§5,7.1,9: AS errors use OAuth JSON; RS errors use a DPoP challenge.
pub(super) fn dpop_error_response(
    issuer: &str,
    role: DpopEndpointRole,
    error: DpopError,
) -> Response {
    let (code, description) = match &error {
        DpopError::UseDpopNonce(_) => (
            "use_dpop_nonce",
            "server requires a nonce in the DPoP proof",
        ),
        DpopError::BackendUnavailable(_) => (
            "temporarily_unavailable",
            "DPoP protection backend unavailable",
        ),
        DpopError::InvalidProof | DpopError::Replay | DpopError::MissingProof => {
            ("invalid_dpop_proof", "DPoP proof validation failed")
        }
    };
    let unavailable = matches!(error, DpopError::BackendUnavailable(_));
    let status = if unavailable {
        StatusCode::SERVICE_UNAVAILABLE
    } else if role == DpopEndpointRole::AuthorizationServer {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::UNAUTHORIZED
    };
    let mut response = no_cache_json_error_with_iss(status, code, Some(description), issuer);
    if role == DpopEndpointRole::ResourceServer && !unavailable {
        apply_oauth_authenticate_header(&mut response, "DPoP", code);
    }
    if let DpopError::UseDpopNonce(nonce) = error {
        match HeaderValue::from_str(&nonce) {
            Ok(value) => {
                response.headers_mut().insert("DPoP-Nonce", value);
            }
            Err(_) => {
                return no_cache_json_error_with_iss(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    None,
                    issuer,
                )
            }
        }
    }
    response
}

#[cfg(test)]
pub(super) fn dpop_use_nonce_response(issuer: &str, nonce: &str) -> Response {
    dpop_error_response(
        issuer,
        DpopEndpointRole::AuthorizationServer,
        DpopError::UseDpopNonce(nonce.into()),
    )
}

pub(super) fn refresh_sender_binding_violation(
    refresh: &RefreshToken,
    sender_binding: Option<&SenderBinding>,
    sender_constraint: SenderConstraint,
    enforce_sender_binding: bool,
) -> Option<&'static str> {
    // An issuance-policy option cannot remove a binding already committed to
    // a refresh token (RFC 9449 §5 / RFC 8705 §3). It only affects unbound grants.
    if !enforce_sender_binding && refresh.sender_binding.is_none() {
        return None;
    }

    let binding = sender_binding;
    match sender_constraint {
        SenderConstraint::DPoP => match (&refresh.sender_binding, binding) {
            (Some(SenderBinding::DPoP { jkt }), Some(SenderBinding::DPoP { jkt: present }))
                if util::jwk_thumbprint_matches(jkt.as_str(), present.as_str()) =>
            {
                None
            }
            (Some(SenderBinding::DPoP { .. }), Some(SenderBinding::DPoP { .. })) => {
                Some("sender_binding_mismatch")
            }
            (Some(SenderBinding::DPoP { .. }), None)
            | (Some(SenderBinding::DPoP { .. }), Some(SenderBinding::Mtls { .. })) => {
                Some("sender_binding_missing")
            }
            (Some(SenderBinding::Mtls { .. }), _) => Some("sender_binding_mismatch"),
            (None, _) => Some("sender_binding_missing"),
        },
        SenderConstraint::Mtls => match (&refresh.sender_binding, binding) {
            (
                Some(SenderBinding::Mtls { fingerprint }),
                Some(SenderBinding::Mtls {
                    fingerprint: present,
                }),
            ) if fingerprint == present => None,
            (Some(SenderBinding::Mtls { .. }), Some(SenderBinding::Mtls { .. })) => {
                Some("sender_binding_mismatch")
            }
            (Some(SenderBinding::Mtls { .. }), None)
            | (Some(SenderBinding::Mtls { .. }), Some(SenderBinding::DPoP { .. })) => {
                Some("sender_binding_missing")
            }
            (Some(SenderBinding::DPoP { .. }), _) => Some("sender_binding_mismatch"),
            (None, _) => Some("sender_binding_missing"),
        },
        SenderConstraint::None => match (&refresh.sender_binding, binding) {
            (Some(SenderBinding::DPoP { jkt }), Some(SenderBinding::DPoP { jkt: present }))
                if util::jwk_thumbprint_matches(jkt.as_str(), present.as_str()) =>
            {
                None
            }
            (
                Some(SenderBinding::Mtls { fingerprint }),
                Some(SenderBinding::Mtls {
                    fingerprint: present,
                }),
            ) if fingerprint == present => None,
            (Some(SenderBinding::DPoP { .. }), Some(SenderBinding::DPoP { .. }))
            | (Some(SenderBinding::Mtls { .. }), Some(SenderBinding::Mtls { .. })) => {
                Some("sender_binding_mismatch")
            }
            (Some(SenderBinding::DPoP { .. }), None | Some(SenderBinding::Mtls { .. }))
            | (Some(SenderBinding::Mtls { .. }), None | Some(SenderBinding::DPoP { .. })) => {
                Some("sender_binding_missing")
            }
            (None, _) => None,
        },
    }
}

pub(super) fn trusted_mtls_fingerprint(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<String>, util::SingleHeaderError> {
    if !state.transport.config().require_tls_proxy {
        return Ok(None);
    }
    match forwarded_client_cert_header(headers)? {
        Some(value) => normalize_forwarded_client_cert(value)
            .map(Some)
            .ok_or(util::SingleHeaderError::InvalidValue),
        None => Ok(None),
    }
}

pub(super) fn token_resolve_sender_binding(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    sender_constraint: SenderConstraint,
    issuer_base: &str,
) -> Result<Option<SenderBinding>, Response> {
    let mtls_fingerprint = trusted_mtls_fingerprint(state, headers)
        .map_err(|err| token_header_error(X_FORWARDED_CLIENT_CERT_HEADER, err))?;
    let dpop_present = dpop_header(headers)
        .map_err(|_| {
            dpop_error_response(
                issuer_base,
                DpopEndpointRole::AuthorizationServer,
                DpopError::InvalidProof,
            )
        })?
        .is_some();
    if sender_constraint == SenderConstraint::Mtls && dpop_present {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("DPoP proof is not allowed when mTLS sender constraint is required"),
        ));
    }
    let path = uri
        .path_and_query()
        .map_or(uri.path(), axum::http::uri::PathAndQuery::as_str);
    let uri_for_dpop: Uri = path.parse().map_err(|_| {
        dpop_error_response(
            issuer_base,
            DpopEndpointRole::AuthorizationServer,
            DpopError::InvalidProof,
        )
    })?;
    let binding = match sender_constraint {
        SenderConstraint::Mtls => None,
        _ => dpop_binding_from_request(
            state.dpop.as_ref(),
            DpopEndpointRole::AuthorizationServer,
            &http::Method::POST,
            &uri_for_dpop,
            headers,
        )
        .map_err(|error| {
            dpop_error_response(issuer_base, DpopEndpointRole::AuthorizationServer, error)
        })?,
    };
    match sender_constraint {
        SenderConstraint::Mtls => mtls_fingerprint
            .map(|fingerprint| SenderBinding::Mtls { fingerprint })
            .ok_or_else(|| {
                token_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    Some("mTLS client certificate fingerprint required"),
                )
            })
            .map(Some),
        SenderConstraint::DPoP => binding
            .map(|binding| SenderBinding::DPoP { jkt: binding.jkt })
            .ok_or_else(|| {
                dpop_error_response(
                    issuer_base,
                    DpopEndpointRole::AuthorizationServer,
                    DpopError::MissingProof,
                )
            })
            .map(Some),
        SenderConstraint::None => Ok(binding
            .map(|binding| SenderBinding::DPoP { jkt: binding.jkt })
            .or_else(|| mtls_fingerprint.map(|fingerprint| SenderBinding::Mtls { fingerprint }))),
    }
}

pub(super) fn token_cnf_from_sender_binding(
    sender_binding: Option<&SenderBinding>,
) -> Option<CnfClaim> {
    sender_binding.and_then(|sender_binding| match sender_binding {
        SenderBinding::DPoP { jkt } => Some(CnfClaim::Jkt(jkt.clone())),
        SenderBinding::Mtls { fingerprint } => {
            mtls_fingerprint_to_x5t_s256(fingerprint).map(CnfClaim::X5tS256)
        }
    })
}

#[cfg(test)]
mod sender_binding_policy_tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    use crate::authcode::types::{
        BearerTokenMeta, BearerTokenMetaInput, RefreshTokenInput, TokenRequest as IssuerTokenReq,
    };

    use super::super::token_endpoint::TokenEndpointContext;
    use super::super::token_exchange::validate_token_exchange_sender_binding;
    use super::super::token_form::TokenForm;
    use super::super::TOKEN_EXCHANGE_GRANT_TYPE;

    fn refresh_with_binding(sender_binding: Option<SenderBinding>) -> RefreshToken {
        let mut refresh = RefreshToken::new(RefreshTokenInput::new(
            "client".to_string(),
            "user".to_string(),
        ));
        refresh.sender_binding = sender_binding;
        refresh
    }

    fn token_exchange_context(sender_binding: Option<SenderBinding>) -> TokenEndpointContext {
        let grant_type = TOKEN_EXCHANGE_GRANT_TYPE.to_string();
        TokenEndpointContext {
            request_id: "test-request".to_string(),
            params: Vec::new(),
            form: TokenForm {
                grant_type: grant_type.clone(),
                code: None,
                client_id: Some("client".to_string()),
                client_secret: None,
                code_verifier: None,
                redirect_uri: None,
                scope: None,
                refresh_token: None,
                assertion: None,
                client_assertion_type: None,
                client_assertion: None,
                device_code: None,
            },
            grant_type: grant_type.clone(),
            client_id: "client".to_string(),
            resource: None,
            sender_constraint: SenderConstraint::None,
            enforce_refresh_sender_binding: true,
            authorization_code_grant_allowed: false,
            refresh_grant_allowed: false,
            sender_binding,
            issuer_req: IssuerTokenReq {
                grant_type,
                code: None,
                redirect_uri: None,
                client_id: "client".to_string(),
                client_secret: None,
                refresh_token: None,
                code_verifier: None,
                resource: None,
                request_object_claims: None,
            },
            cnf_for_at: None,
        }
    }

    fn bearer_meta_with_binding(sender_binding: Option<SenderBinding>) -> BearerTokenMeta {
        BearerTokenMeta::new(BearerTokenMetaInput {
            token_id: "access-token".to_string(),
            client_id: "client".to_string(),
            user_id: "user".to_string(),
            granted_scopes: vec!["read".to_string()],
            audience: "client".to_string(),
            sender_binding,
            authorization_details: None,
            auth_time_epoch_secs: None,
            acr: None,
            issued_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(300),
            refresh_parent: None,
        })
    }

    #[test]
    fn refresh_sender_constraint_none_allows_unbound_refresh() {
        let refresh = refresh_with_binding(None);

        assert!(
            refresh_sender_binding_violation(&refresh, None, SenderConstraint::None, true,)
                .is_none()
        );
    }

    #[test]
    fn refresh_sender_constraint_none_still_enforces_bound_refresh() {
        let jkt = "test-jkt";
        let refresh = refresh_with_binding(Some(SenderBinding::DPoP {
            jkt: util::jwk_thumbprint_uri_from_jkt(jkt),
        }));
        let matching = SenderBinding::DPoP {
            jkt: jkt.to_string(),
        };
        let mismatched = SenderBinding::DPoP {
            jkt: "other-jkt".to_string(),
        };

        assert!(refresh_sender_binding_violation(
            &refresh,
            Some(&matching),
            SenderConstraint::None,
            true,
        )
        .is_none());
        assert_eq!(
            refresh_sender_binding_violation(&refresh, None, SenderConstraint::None, true),
            Some("sender_binding_missing")
        );
        assert_eq!(
            refresh_sender_binding_violation(
                &refresh,
                Some(&mismatched),
                SenderConstraint::None,
                true,
            ),
            Some("sender_binding_mismatch")
        );
    }

    #[test]
    fn disabling_refresh_policy_cannot_remove_committed_sender_binding() {
        for binding in [
            SenderBinding::DPoP {
                jkt: "original".into(),
            },
            SenderBinding::Mtls {
                fingerprint: "original".into(),
            },
        ] {
            let refresh = refresh_with_binding(Some(binding.clone()));
            assert!(refresh_sender_binding_violation(
                &refresh,
                Some(&binding),
                SenderConstraint::None,
                false
            )
            .is_none());
            assert!(refresh_sender_binding_violation(
                &refresh,
                None,
                SenderConstraint::None,
                false
            )
            .is_some());
            for wrong in [
                SenderBinding::DPoP {
                    jkt: "wrong".into(),
                },
                SenderBinding::Mtls {
                    fingerprint: "wrong".into(),
                },
            ] {
                assert!(refresh_sender_binding_violation(
                    &refresh,
                    Some(&wrong),
                    SenderConstraint::None,
                    false
                )
                .is_some());
            }
        }
    }

    #[test]
    fn token_exchange_sender_binding_accepts_thumbprint_uri() {
        let jkt = "test-jkt";
        let ctx = token_exchange_context(Some(SenderBinding::DPoP {
            jkt: jkt.to_string(),
        }));
        let subject_meta = bearer_meta_with_binding(Some(SenderBinding::DPoP {
            jkt: util::jwk_thumbprint_uri_from_jkt(jkt),
        }));

        assert!(validate_token_exchange_sender_binding(&ctx, &subject_meta).is_ok());
    }
}
