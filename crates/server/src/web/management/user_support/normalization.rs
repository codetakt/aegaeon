use axum::{http::StatusCode, response::Response};

use crate::management::types::UpdateUserProfileRequest;

use super::super::error_response;
use super::errors::invalid_email_response;

pub(in crate::web::management) fn normalize_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return None;
    }
    Some(email)
}

pub(in crate::web::management) fn normalize_subject(raw: &str) -> Option<String> {
    let subject = raw.trim();
    if subject.is_empty() {
        return None;
    }
    Some(subject.to_owned())
}

pub(in crate::web::management) fn ensure_user_profile_update_requested(
    body: &UpdateUserProfileRequest,
    request_id: &str,
) -> Result<(), Response> {
    if body.email.is_none()
        && body.email_verified.is_none()
        && body.display_name.is_none()
        && body.custom_claims.is_none()
    {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "At least one profile field must be updated",
            None,
            Some(request_id),
        ));
    }

    Ok(())
}

pub(in crate::web::management) fn normalize_required_subject(
    subject: &str,
    request_id: &str,
) -> Result<String, Response> {
    normalize_subject(subject).ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Subject must not be empty",
            None,
            Some(request_id),
        )
    })
}

pub(in crate::web::management) fn normalize_optional_email(
    email: Option<&str>,
    request_id: &str,
) -> Result<Option<String>, Response> {
    email
        .map(|raw| normalize_email(raw).ok_or_else(|| invalid_email_response(request_id)))
        .transpose()
}
