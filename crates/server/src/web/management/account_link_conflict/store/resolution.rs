use super::super::super::{
    error_response, load_account_link_summary_by_id_required, management_internal_error,
    AccountLinkRefreshTokenAction, ManagementEnvironmentScope,
};
use super::super::plan::AccountLinkConflictResolutionPlan;
use crate::management::types::AccountLinkSummary;
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management::account_link_conflict) async fn apply_account_link_conflict_resolution(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    target_end_user_id: Uuid,
    existing_account_link: &AccountLinkSummary,
    plan: &AccountLinkConflictResolutionPlan,
    request_id: &str,
) -> Result<AccountLinkSummary, Response> {
    if plan.moving_to_different_user {
        let result = match plan.refresh_token_action {
            Some(AccountLinkRefreshTokenAction::Clear) => {
                sqlx::query(
                    r"
UPDATE aegaeon.account_links
SET end_user_id = $1,
    upstream_refresh_token_encrypted = NULL,
    upstream_refresh_token_connection_id = NULL,
    upstream_refresh_token_generation = 0
WHERE id = $2
  AND environment_id = $3
            ",
                )
                .bind(target_end_user_id)
                .bind(plan.existing_account_link_id)
                .bind(scope.environment)
                .execute(&mut **tx)
                .await
            }
            _ => {
                sqlx::query(
                    r"
UPDATE aegaeon.account_links
SET end_user_id = $1
WHERE id = $2
  AND environment_id = $3
            ",
                )
                .bind(target_end_user_id)
                .bind(plan.existing_account_link_id)
                .bind(scope.environment)
                .execute(&mut **tx)
                .await
            }
        };

        match result {
            Ok(result) if result.rows_affected() > 0 => {}
            Ok(_) => {
                return Err(error_response(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "Account link conflict not found",
                    None,
                    Some(request_id),
                ));
            }
            Err(_) => {
                return Err(management_internal_error(
                    request_id,
                    "Failed to resolve account link conflict",
                ));
            }
        }

        return load_account_link_summary_by_id_required(
            &mut **tx,
            scope,
            plan.existing_account_link_id,
            request_id,
        )
        .await;
    }

    Ok(existing_account_link.clone())
}
