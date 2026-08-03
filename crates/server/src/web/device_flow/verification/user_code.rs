use super::super::super::form_helpers::{
    form_field, reject_duplicate_form_fields, try_validate_form_csrf_async,
};
use super::super::super::oauth_errors::no_cache_json_error_with_iss;
use super::super::super::request_admission::{
    enforce_no_credentials_in_uri, enforce_no_credentials_in_uri_with_policy, validate_raw_query,
    BoundedQueryLimits, QueryCredentialPolicy,
};
use super::super::super::{transport_rejection, AppState};
use axum::{
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use std::net::SocketAddr;

use super::response::{
    device_csrf_store_unavailable_response, device_html_response_with_csrf_cookie,
    device_user_code_form_response_async, try_device_csrf_token_async, DEVICE_CSRF_COOKIE_NAME,
};

/// GET /device — show the user code entry form.
/// Supports `?user_code=XXXX-XXXX` pre-fill from `verification_uri_complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web) enum DeviceUserCodeQueryError {
    Malformed,
    DuplicateUserCode,
}

const DEVICE_USER_CODE_QUERY_LIMITS: BoundedQueryLimits = BoundedQueryLimits::new(1024, 8, 64, 256);

pub(in crate::web) fn parse_device_user_code_query(
    uri: &Uri,
) -> Result<Option<String>, DeviceUserCodeQueryError> {
    let Some(query) = uri.query() else {
        return Ok(None);
    };
    validate_raw_query(Some(query), DEVICE_USER_CODE_QUERY_LIMITS)
        .map_err(|_| DeviceUserCodeQueryError::Malformed)?;
    let params = serde_urlencoded::from_str::<Vec<(String, String)>>(query)
        .map_err(|_| DeviceUserCodeQueryError::Malformed)?;
    params
        .into_iter()
        .try_fold(None, |user_code, (key, value)| {
            if key != "user_code" {
                return Ok(user_code);
            }
            if user_code.is_some() {
                Err(DeviceUserCodeQueryError::DuplicateUserCode)
            } else {
                Ok(Some(value))
            }
        })
}

pub(in crate::web) async fn device_verify_get(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let issuer_base = state.issuer.as_str();
    if !state.cfg.grant_runtime().device_authorization_enabled() {
        return no_cache_json_error_with_iss(StatusCode::NOT_FOUND, "not_found", None, issuer_base);
    }
    if let Err(resp) = enforce_no_credentials_in_uri_with_policy(
        &uri,
        issuer_base,
        QueryCredentialPolicy::allow(&["user_code"]),
    ) {
        return resp;
    }
    let user_code = match parse_device_user_code_query(&uri) {
        Ok(user_code) => user_code,
        Err(_) => {
            return device_user_code_form_response_async(
                state.device.csrf_store.clone(),
                StatusCode::BAD_REQUEST,
                None,
                Some("Invalid verification link."),
            )
            .await;
        }
    };
    device_user_code_form_response_async(
        state.device.csrf_store.clone(),
        StatusCode::OK,
        user_code.as_deref(),
        None,
    )
    .await
}

struct DeviceVerificationSubmission {
    params: Vec<(String, String)>,
    user_code: Option<String>,
}

async fn invalid_device_verification_form_response(state: &AppState) -> Response {
    device_user_code_form_response_async(
        state.device.csrf_store.clone(),
        StatusCode::BAD_REQUEST,
        None,
        Some("Invalid form submission."),
    )
    .await
}

fn enforce_device_verify_post_admission(
    state: &AppState,
    uri: &Uri,
    issuer_base: &str,
) -> Result<(), Response> {
    if !state.cfg.grant_runtime().device_authorization_enabled() {
        return Err(no_cache_json_error_with_iss(
            StatusCode::NOT_FOUND,
            "not_found",
            None,
            issuer_base,
        ));
    }
    enforce_no_credentials_in_uri(uri, issuer_base)
}

async fn device_verification_submission(
    state: &AppState,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
) -> Result<DeviceVerificationSubmission, Response> {
    let Ok(axum::extract::Form(params)) = form else {
        return Err(invalid_device_verification_form_response(state).await);
    };
    if reject_duplicate_form_fields(&params, &["csrf_token", "user_code"]).is_err() {
        return Err(invalid_device_verification_form_response(state).await);
    }
    let user_code = form_field(&params, "user_code").ok().flatten();
    Ok(DeviceVerificationSubmission { params, user_code })
}

async fn validate_device_verify_csrf(
    state: &AppState,
    headers: &HeaderMap,
    submission: &DeviceVerificationSubmission,
) -> Result<(), Response> {
    match try_validate_form_csrf_async(
        headers,
        &submission.params,
        DEVICE_CSRF_COOKIE_NAME,
        state.device.csrf_store.clone(),
    )
    .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(device_user_code_form_response_async(
            state.device.csrf_store.clone(),
            StatusCode::FORBIDDEN,
            submission.user_code.as_deref(),
            Some("Session expired. Please try again."),
        )
        .await),
        Err(err) => Err(device_csrf_store_unavailable_response(&err)),
    }
}

async fn require_device_verify_user_code(
    state: &AppState,
    user_code: Option<&str>,
) -> Result<String, Response> {
    match user_code
        .map(str::trim)
        .filter(|code| !code.is_empty())
        .map(ToString::to_string)
    {
        Some(user_code) => Ok(user_code),
        None => Err(device_user_code_form_response_async(
            state.device.csrf_store.clone(),
            StatusCode::BAD_REQUEST,
            None,
            Some("Please enter a user code."),
        )
        .await),
    }
}

async fn enforce_device_verify_rate_limit(
    state: &AppState,
    remote: SocketAddr,
    headers: &HeaderMap,
    user_code: &str,
) -> Result<(), Response> {
    let subject = state
        .transport
        .rate_limit_subject(Some(remote), headers)
        .map_err(|kind| transport_rejection(state, kind))?;
    match state
        .device
        .rate_limiter
        .clone()
        .try_check_async(subject)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(device_user_code_form_response_async(
            state.device.csrf_store.clone(),
            StatusCode::TOO_MANY_REQUESTS,
            Some(user_code),
            Some("Too many attempts. Please wait and try again."),
        )
        .await),
        Err(err) => {
            tracing::error!(error = %err, "device verification rate limiter unavailable");
            Err(device_user_code_form_response_async(
                state.device.csrf_store.clone(),
                StatusCode::SERVICE_UNAVAILABLE,
                Some(user_code),
                Some("Device verification is temporarily unavailable. Please try again."),
            )
            .await)
        }
    }
}

async fn device_verification_confirmation_response(state: &AppState, user_code: &str) -> Response {
    let lookup = match state
        .device
        .code_store
        .try_lookup_by_user_code_async(user_code.to_string())
        .await
    {
        Ok(lookup) => lookup,
        Err(err) => {
            tracing::error!(error = %err, "device code lookup store unavailable");
            return device_user_code_form_response_async(
                state.device.csrf_store.clone(),
                StatusCode::SERVICE_UNAVAILABLE,
                Some(user_code),
                Some("Device verification is temporarily unavailable. Please try again."),
            )
            .await;
        }
    };
    if let Some(lookup) = lookup {
        let csrf_token = match try_device_csrf_token_async(state.device.csrf_store.clone()).await {
            Ok(token) => token,
            Err(response) => return response,
        };
        let html = crate::device_authz::render_confirm_page(
            &csrf_token,
            user_code,
            &lookup.client_id,
            lookup.scope.as_deref(),
            lookup.resource.as_deref(),
        );
        device_html_response_with_csrf_cookie(StatusCode::OK, html, &csrf_token)
    } else {
        device_user_code_form_response_async(
            state.device.csrf_store.clone(),
            StatusCode::BAD_REQUEST,
            Some(user_code),
            Some("Invalid or expired code. Please check and try again."),
        )
        .await
    }
}

pub(in crate::web) async fn device_verify_post(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    let issuer_base = state.issuer.as_str();
    if let Err(response) = enforce_device_verify_post_admission(&state, &uri, issuer_base) {
        return response;
    }

    let submission = match device_verification_submission(&state, form).await {
        Ok(submission) => submission,
        Err(response) => return response,
    };
    if let Err(response) = validate_device_verify_csrf(&state, &headers, &submission).await {
        return response;
    }
    let user_code =
        match require_device_verify_user_code(&state, submission.user_code.as_deref()).await {
            Ok(user_code) => user_code,
            Err(response) => return response,
        };
    if let Err(response) =
        enforce_device_verify_rate_limit(&state, remote, &headers, &user_code).await
    {
        return response;
    }
    device_verification_confirmation_response(&state, &user_code).await
}
