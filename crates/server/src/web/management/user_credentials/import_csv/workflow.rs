use super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    UserManagementContext,
};
use super::super::environment::load_environment_issuer_url;
use super::super::policy::load_recovery_token_ttl_policy_in_transaction;
use super::{
    parser::parse_import_users_csv,
    row::{import_csv_user_row, imported_user_row_response},
};
use crate::local_credentials::{self, RecoveryTokenPurpose};
use crate::management::types::{ImportUsersCsvRequest, ImportUsersCsvResponse};
use axum::{http::StatusCode, response::Response};

pub(super) async fn import_users_csv_inner(
    context: &UserManagementContext,
    body: &ImportUsersCsvRequest,
    request_id: &str,
) -> Result<ImportUsersCsvResponse, Response> {
    let rows = parse_import_users_csv(&body.csv).map_err(|message| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &message,
            None,
            Some(request_id),
        )
    })?;
    let issuer_url = load_environment_issuer_url(
        &context.pool,
        context.team_id,
        context.environment_id,
        request_id,
    )
    .await?;
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    let activation_ttl = if body.issue_activation_tokens {
        let ttl_policy = load_recovery_token_ttl_policy_in_transaction(
            &mut tx,
            context.environment_id,
            request_id,
        )
        .await?;
        Some(
            local_credentials::sanitize_recovery_token_ttl(
                body.activation_token_expires_in_seconds,
                RecoveryTokenPurpose::Activation,
                ttl_policy,
            )
            .map_err(|message| {
                error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    message,
                    None,
                    Some(request_id),
                )
            })?,
        )
    } else {
        None
    };

    let mut imported_users = Vec::new();
    for row in rows {
        imported_users.push(
            import_csv_user_row(
                &mut tx,
                context,
                row,
                &issuer_url,
                activation_ttl,
                request_id,
            )
            .await?,
        );
    }

    commit_management_transaction(tx, request_id).await?;
    let mut response_rows = Vec::with_capacity(imported_users.len());
    for row in imported_users {
        response_rows.push(imported_user_row_response(&context.pool, row, request_id).await?);
    }

    Ok(ImportUsersCsvResponse {
        imported_users: response_rows,
    })
}
