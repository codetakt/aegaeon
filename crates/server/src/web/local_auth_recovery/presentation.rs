use super::super::local_auth_support::{
    local_auth_response_with_csrf_cookie, try_local_csrf_token, try_local_csrf_token_async,
};
use super::super::{render_local_password_form, LocalPasswordForm};
use crate::device_authz::CsrfTokenStore;
use crate::local_credentials::RecoveryTokenPurpose;
use axum::response::Response;
use http::StatusCode;
use std::sync::Arc;

pub(super) struct LocalRecoveryPresentation {
    pub(super) title: &'static str,
    pub(super) action: &'static str,
    pub(super) failure_event_type: &'static str,
}

#[must_use]
pub(super) fn local_recovery_presentation(
    purpose: RecoveryTokenPurpose,
) -> LocalRecoveryPresentation {
    match purpose {
        RecoveryTokenPurpose::Activation => LocalRecoveryPresentation {
            title: "Activate account",
            action: "/auth/activate",
            failure_event_type: "auth.local.activation.failed.v1",
        },
        RecoveryTokenPurpose::PasswordReset => LocalRecoveryPresentation {
            title: "Reset password",
            action: "/auth/password/reset",
            failure_event_type: "auth.local.passwordReset.failed.v1",
        },
    }
}

pub(super) fn local_recovery_form_response(
    csrf_store: &CsrfTokenStore,
    status: StatusCode,
    purpose: RecoveryTokenPurpose,
    token: Option<&str>,
    return_to: Option<&str>,
    message: &str,
) -> Response {
    let presentation = local_recovery_presentation(purpose);
    let csrf_token = match try_local_csrf_token(csrf_store) {
        Ok(token) => token,
        Err(response) => return response,
    };
    local_auth_response_with_csrf_cookie(
        status,
        render_local_password_form(LocalPasswordForm {
            title: presentation.title,
            heading: presentation.title,
            action: presentation.action,
            submit_label: presentation.title,
            token,
            return_to,
            csrf_token: &csrf_token,
            error: Some(message),
        }),
        &csrf_token,
    )
}

pub(super) async fn local_recovery_form_response_async(
    csrf_store: Arc<CsrfTokenStore>,
    status: StatusCode,
    purpose: RecoveryTokenPurpose,
    token: Option<&str>,
    return_to: Option<&str>,
    message: &str,
) -> Response {
    let presentation = local_recovery_presentation(purpose);
    let csrf_token = match try_local_csrf_token_async(csrf_store).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    local_auth_response_with_csrf_cookie(
        status,
        render_local_password_form(LocalPasswordForm {
            title: presentation.title,
            heading: presentation.title,
            action: presentation.action,
            submit_label: presentation.title,
            token,
            return_to,
            csrf_token: &csrf_token,
            error: Some(message),
        }),
        &csrf_token,
    )
}
