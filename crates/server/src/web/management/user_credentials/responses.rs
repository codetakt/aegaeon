use super::super::management_internal_error;
use crate::local_credentials;
use crate::management::types::{
    IssueRecoveryTokenResponse, PasswordCredential, RecoveryToken, UserCredentialsResponse,
};
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn load_issued_recovery_token_response_required(
    pool: &PgPool,
    user_id: Uuid,
    issued: local_credentials::IssuedRecoveryToken,
    redeem_url: String,
    request_id: &str,
) -> Result<IssueRecoveryTokenResponse, Response> {
    reload_issued_recovery_token_response(pool, user_id, issued, redeem_url, request_id)
        .await?
        .ok_or_else(|| {
            management_internal_error(request_id, "Failed to reload recovery token state")
        })
}

pub(super) async fn load_user_credentials_response(
    pool: &PgPool,
    user_id: Uuid,
    request_id: &str,
) -> Result<UserCredentialsResponse, Response> {
    local_credentials::load_user_credential_state(pool, user_id)
        .await
        .map(user_credentials_response_from_state)
        .map_err(|_| management_internal_error(request_id, "Failed to load credential state"))
}

fn password_credential_from_record(
    record: local_credentials::PasswordCredentialRecord,
) -> PasswordCredential {
    PasswordCredential {
        id: record.id,
        status: record.status,
        created_at: record.created_at,
        updated_at: record.updated_at,
        last_used_at: record.last_used_at,
    }
}

fn recovery_token_from_record(record: local_credentials::RecoveryTokenRecord) -> RecoveryToken {
    RecoveryToken {
        id: record.id,
        purpose: record.purpose,
        status: record.status,
        expires_at: record.expires_at,
        redeemed_at: record.redeemed_at,
        revoked_at: record.revoked_at,
        created_at: record.created_at,
    }
}

fn issued_recovery_token_response_from_state(
    state: local_credentials::UserCredentialState,
    issued: local_credentials::IssuedRecoveryToken,
    redeem_url: String,
) -> Option<IssueRecoveryTokenResponse> {
    state
        .recovery_tokens
        .into_iter()
        .find(|record| record.id == issued.id)
        .map(|record| IssueRecoveryTokenResponse {
            token: issued.token,
            redeem_url,
            recovery_token: recovery_token_from_record(record),
        })
}

async fn reload_issued_recovery_token_response(
    pool: &PgPool,
    user_id: Uuid,
    issued: local_credentials::IssuedRecoveryToken,
    redeem_url: String,
    request_id: &str,
) -> Result<Option<IssueRecoveryTokenResponse>, Response> {
    let state = local_credentials::load_user_credential_state(pool, user_id)
        .await
        .map_err(|_| {
            management_internal_error(request_id, "Failed to reload recovery token state")
        })?;
    Ok(issued_recovery_token_response_from_state(
        state, issued, redeem_url,
    ))
}

fn user_credentials_response_from_state(
    state: local_credentials::UserCredentialState,
) -> UserCredentialsResponse {
    UserCredentialsResponse {
        password: state.password.map(password_credential_from_record),
        recovery_tokens: state
            .recovery_tokens
            .into_iter()
            .map(recovery_token_from_record)
            .collect(),
    }
}
