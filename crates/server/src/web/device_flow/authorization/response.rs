use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::util;

use super::super::super::oauth_errors::no_cache_json_error_with_iss;
use super::super::super::AppState;
use super::client_auth::DeviceAuthorizationClientContext;
use super::form::DeviceAuthorizationForm;

pub(super) async fn create_device_authorization_response(
    state: &AppState,
    issuer_base: &str,
    client_context: &DeviceAuthorizationClientContext,
    device_form: &DeviceAuthorizationForm,
) -> Response {
    let verification_uri = format!("{issuer_base}/device");
    let Some(resp) = state
        .device
        .code_store
        .try_create_with_resource_async(
            client_context.client_id.clone(),
            device_form.scope.clone(),
            device_form.resource.clone(),
            None,
            verification_uri.clone(),
        )
        .await
    else {
        return no_cache_json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("failed to allocate a unique device user code"),
            issuer_base,
        );
    };

    let mut body = serde_json::json!({
        "device_code": resp.device_code,
        "user_code": resp.user_code,
        "verification_uri": resp.verification_uri,
        "expires_in": resp.expires_in,
        "interval": resp.interval,
    });
    if let Some(complete) = resp.verification_uri_complete {
        body["verification_uri_complete"] = serde_json::json!(complete);
    }

    let mut response = (StatusCode::OK, Json(body)).into_response();
    util::apply_no_cache_headers(&mut response);
    response
}
