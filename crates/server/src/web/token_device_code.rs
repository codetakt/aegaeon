use axum::{http::StatusCode, response::Response};
use serde_json::json;
use std::time::SystemTime;

use crate::authcode::types::{AccessToken, BearerTokenMeta, BearerTokenMetaInput};
use crate::authcode::BearerAccessTokenMint;
use crate::client_registry::ClientRegistry;
use crate::device_authz::DevicePollResult;

use super::{
    access_token_expires_at, oauth_audit::require_token_issue_audit, scope_members,
    token_error_response, token_internal_error_response, token_json_response,
    token_registry_state_error_response, AppState, TokenEndpointContext, DEVICE_CODE_GRANT_TYPE,
};

struct ApprovedDeviceGrant {
    user_id: String,
    scope: Option<String>,
    resource: Option<String>,
    client_id: String,
}

fn required_device_code(ctx: &TokenEndpointContext) -> Result<String, Response> {
    ctx.form
        .device_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            token_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("device_code is required"),
            )
        })
}

fn validate_device_code_client_grant(
    clients: &ClientRegistry,
    client_id: &str,
) -> Result<(), Response> {
    if clients
        .try_allows_grant(client_id, DEVICE_CODE_GRANT_TYPE)
        .map_err(|error| token_registry_state_error_response("device_code_allows_grant", error))?
    {
        Ok(())
    } else {
        Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            None,
        ))
    }
}

fn device_poll_rejection_response(result: &DevicePollResult) -> Response {
    match result {
        DevicePollResult::AuthorizationPending => {
            token_error_response(StatusCode::BAD_REQUEST, "authorization_pending", None)
        }
        DevicePollResult::SlowDown => {
            token_error_response(StatusCode::BAD_REQUEST, "slow_down", None)
        }
        DevicePollResult::ExpiredToken => {
            token_error_response(StatusCode::BAD_REQUEST, "expired_token", None)
        }
        DevicePollResult::AccessDenied => {
            token_error_response(StatusCode::BAD_REQUEST, "access_denied", None)
        }
        DevicePollResult::InvalidTarget => {
            token_error_response(StatusCode::BAD_REQUEST, "invalid_target", None)
        }
        DevicePollResult::Approved { .. } => token_internal_error_response(
            "device_code_poll_state",
            Some("approved device poll result reached rejection path"),
        ),
    }
}

fn device_access_token_timing(state: &AppState) -> Result<(u64, SystemTime, SystemTime), Response> {
    let expires_in = state.tokens.issuer.access_token_ttl_secs();
    let now = SystemTime::now();
    let expires_at = access_token_expires_at(now, expires_in).map_err(|error| {
        token_internal_error_response("device_code_access_token_expiry", Some(&error))
    })?;
    Ok((expires_in, now, expires_at))
}

async fn approved_device_grant_response(
    state: &AppState,
    ctx: &TokenEndpointContext,
    grant: ApprovedDeviceGrant,
) -> Response {
    let (expires_in, now, expires_at) = match device_access_token_timing(state) {
        Ok(timing) => timing,
        Err(response) => return response,
    };
    let audience = grant
        .resource
        .clone()
        .unwrap_or_else(|| grant.client_id.clone());
    let access_token = match state
        .tokens
        .issuer
        .mint_bearer_access_token(BearerAccessTokenMint {
            client_id: &grant.client_id,
            subject: &grant.user_id,
            scope: grant.scope.as_deref(),
            audience: &audience,
            issued_at: now,
            expires_in,
            auth_time_epoch_secs: None,
            acr: None,
            cnf: ctx.cnf_for_at.as_ref(),
        }) {
        Ok(token) => token,
        Err(error) => {
            return token_internal_error_response(
                "device_code_access_token_mint",
                Some(error.as_str()),
            );
        }
    };
    let access = AccessToken {
        token: access_token.clone(),
        token_type: "Bearer".to_string(),
        client_id: grant.client_id.clone(),
        user_id: grant.user_id.clone(),
        scope: grant.scope.clone(),
        expires_in,
        created_at: now,
        cnf: ctx.cnf_for_at.clone(),
    };
    let granted_scopes = match scope_members(grant.scope.as_deref()) {
        Ok(scopes) => scopes,
        Err(error) => {
            return token_internal_error_response(
                "device_code_scope_admission",
                Some(&error.to_string()),
            );
        }
    };
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access_token.clone(),
        client_id: grant.client_id,
        user_id: grant.user_id,
        granted_scopes,
        audience,
        sender_binding: ctx.sender_binding.clone(),
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: now,
        expires_at,
        refresh_parent: None,
    });
    if let Err(error) = state
        .tokens
        .store
        .store_issued_grant_async(access, None, meta)
        .await
        .map(|_| ())
    {
        return token_internal_error_response("device_code_access_token_store", Some(&error));
    }
    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    });
    if let Some(scope) = grant.scope {
        body["scope"] = json!(scope);
    }
    token_json_response(StatusCode::OK, body)
}

pub(super) async fn handle_token_device_code_grant(
    state: &AppState,
    ctx: &TokenEndpointContext,
) -> Response {
    if !state.cfg.grant_runtime().device_authorization_enabled() {
        return token_error_response(StatusCode::BAD_REQUEST, "unsupported_grant_type", None);
    }
    if let Err(response) = validate_device_code_client_grant(&state.clients, &ctx.client_id) {
        return response;
    }
    let device_code = match required_device_code(ctx) {
        Ok(device_code) => device_code,
        Err(response) => return response,
    };
    if let Err(response) = require_token_issue_audit(state, state.issuer.as_str(), ctx, None).await
    {
        return response;
    }
    let poll = match state
        .device
        .code_store
        .try_poll_async(
            device_code,
            ctx.client_id.clone(),
            None,
            ctx.resource.clone(),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => return token_internal_error_response("device_code_poll", Some(&error)),
    };
    match poll {
        DevicePollResult::Approved {
            user_id,
            scope,
            resource,
            client_id,
        } => {
            approved_device_grant_response(
                state,
                ctx,
                ApprovedDeviceGrant {
                    user_id,
                    scope,
                    resource,
                    client_id,
                },
            )
            .await
        }
        result => device_poll_rejection_response(&result),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_registry::RegisteredClient;

    fn client_with_grants(grants: &[&str]) -> RegisteredClient {
        RegisteredClient {
            client_id: "device-client".to_string(),
            client_secret: Some("device-secret".to_string()),
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            jwks_pem: None,
            inline_jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            allowed_scopes: vec!["read".to_string()],
            allowed_grant_types: grants.iter().map(|grant| (*grant).to_string()).collect(),
            registration_access_token: None,
            client_id_issued_at: None,
        }
    }

    #[test]
    fn device_code_client_grant_accepts_registered_allowlist() {
        let clients = ClientRegistry::new_process_local_for_tests();
        clients.register(client_with_grants(&[DEVICE_CODE_GRANT_TYPE]));

        assert!(validate_device_code_client_grant(&clients, "device-client").is_ok());
    }

    #[test]
    fn device_code_client_grant_rejects_missing_registered_allowlist() {
        let clients = ClientRegistry::new_process_local_for_tests();
        clients.register(client_with_grants(&["authorization_code"]));

        let response = validate_device_code_client_grant(&clients, "device-client")
            .expect_err("device_code grant must be explicitly registered");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn device_code_client_grant_rejects_unknown_client() {
        let clients = ClientRegistry::new_process_local_for_tests();

        let response = validate_device_code_client_grant(&clients, "missing-client")
            .expect_err("unknown clients must not pass the device_code grant gate");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
