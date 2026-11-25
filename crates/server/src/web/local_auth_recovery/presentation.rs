use super::super::local_auth_support::{
    local_auth_response_with_csrf_cookie, try_local_csrf_token_async,
};
use super::super::{render_local_password_form, LocalPasswordForm};
use crate::device_authz::CsrfTokenStore;
use crate::local_credentials::RecoveryTokenPurpose;
use axum::response::Response;
use http::StatusCode;
use std::sync::Arc;

/// What a recovery form response needs: the CSRF store that issues its
/// replacement token and the page presentation.
pub(in crate::web) struct RecoveryContext<'a> {
    pub(super) csrf_store: Arc<CsrfTokenStore>,
    pub(super) presentation: crate::web::presentation::Presentation<'a>,
}

impl<'a> RecoveryContext<'a> {
    pub(in crate::web) const fn new(
        csrf_store: Arc<CsrfTokenStore>,
        presentation: crate::web::presentation::Presentation<'a>,
    ) -> Self {
        Self {
            csrf_store,
            presentation,
        }
    }
}

pub(super) struct LocalRecoveryPresentation {
    pub(super) title: fn(&crate::web::presentation::Messages) -> &'static str,
    pub(super) action: &'static str,
    pub(super) failure_event_type: &'static str,
}

#[must_use]
pub(super) fn local_recovery_presentation(
    purpose: RecoveryTokenPurpose,
) -> LocalRecoveryPresentation {
    match purpose {
        RecoveryTokenPurpose::Activation => LocalRecoveryPresentation {
            title: |messages| messages.activate_account,
            action: "/auth/activate",
            failure_event_type: "auth.local.activation.failed.v1",
        },
        RecoveryTokenPurpose::PasswordReset => LocalRecoveryPresentation {
            title: |messages| messages.reset_password,
            action: "/auth/password/reset",
            failure_event_type: "auth.local.passwordReset.failed.v1",
        },
    }
}

pub(super) async fn local_recovery_form_response(
    context: &RecoveryContext<'_>,
    status: StatusCode,
    purpose: RecoveryTokenPurpose,
    token: Option<&str>,
    return_to: Option<&str>,
    message: &str,
) -> Response {
    let kind = local_recovery_presentation(purpose);
    let title = (kind.title)(context.presentation.messages());
    let csrf_token =
        match try_local_csrf_token_async(context.presentation, context.csrf_store.clone()).await {
            Ok(token) => token,
            Err(response) => return response,
        };
    local_auth_response_with_csrf_cookie(
        status,
        render_local_password_form(LocalPasswordForm {
            presentation: context.presentation,
            title,
            heading: title,
            action: kind.action,
            submit_label: title,
            token,
            return_to,
            csrf_token: &csrf_token,
            error: Some(message),
        }),
        &csrf_token,
    )
}

pub(super) async fn local_recovery_form_response_async(
    context: RecoveryContext<'_>,
    status: StatusCode,
    purpose: RecoveryTokenPurpose,
    token: Option<&str>,
    return_to: Option<&str>,
    message: &str,
) -> Response {
    local_recovery_form_response(&context, status, purpose, token, return_to, message).await
}
