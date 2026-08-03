use super::super::super::management_internal_error;
use crate::local_credentials::{self, RecoveryTokenPurpose};
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management::user_credentials) async fn issue_recovery_token_with_redeem_url(
    tx: &mut Transaction<'_, Postgres>,
    issuer_url: &str,
    user_id: Uuid,
    purpose: RecoveryTokenPurpose,
    expires_in_secs: i64,
    administrator_id: Uuid,
    request_id: &str,
) -> Result<(local_credentials::IssuedRecoveryToken, String), Response> {
    let issued = local_credentials::issue_recovery_token(
        tx,
        user_id,
        purpose,
        expires_in_secs,
        Some(administrator_id),
        Some(administrator_id),
    )
    .await
    .map_err(|_| {
        let message = match purpose {
            RecoveryTokenPurpose::Activation => "Failed to issue activation token",
            RecoveryTokenPurpose::PasswordReset => "Failed to issue recovery token",
        };
        management_internal_error(request_id, message)
    })?;
    let redeem_url = build_recovery_redeem_url(issuer_url, purpose, &issued.token);

    Ok((issued, redeem_url))
}

fn build_recovery_redeem_url(
    issuer_url: &str,
    purpose: RecoveryTokenPurpose,
    token: &str,
) -> String {
    let path = match purpose {
        RecoveryTokenPurpose::Activation => "/auth/activate",
        RecoveryTokenPurpose::PasswordReset => "/auth/password/reset",
    };
    let encoded_token: String = url::form_urlencoded::byte_serialize(token.as_bytes()).collect();
    format!(
        "{}{}?token={}",
        issuer_url.trim_end_matches('/'),
        path,
        encoded_token
    )
}
