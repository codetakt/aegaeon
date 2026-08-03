use crate::web::management::{
    error_response, management_internal_error, AccountLinkRefreshTokenAction,
};
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) struct AccountLinkRelinkRowUpdateMessages<'a> {
    pub(in crate::web::management) not_found: &'a str,
    pub(in crate::web::management) failure: &'a str,
}

pub(in crate::web::management) async fn relink_account_links_rows(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    target_end_user_id: Uuid,
    account_link_ids: &[Uuid],
    refresh_token_action: Option<AccountLinkRefreshTokenAction>,
    request_id: &str,
    messages: AccountLinkRelinkRowUpdateMessages<'_>,
) -> Result<(), Response> {
    if account_link_ids.is_empty() {
        return Ok(());
    }

    let result = match refresh_token_action {
        Some(AccountLinkRefreshTokenAction::Clear) => {
            sqlx::query(
                r"
UPDATE aegaeon.account_links
SET end_user_id = $1,
    upstream_refresh_token_encrypted = NULL,
    upstream_refresh_token_connection_id = NULL,
    upstream_refresh_token_generation = 0
WHERE environment_id = $2
  AND id = ANY($3::uuid[])
        ",
            )
            .bind(target_end_user_id)
            .bind(environment_id)
            .bind(account_link_ids)
            .execute(&mut **tx)
            .await
        }
        _ => {
            sqlx::query(
                r"
UPDATE aegaeon.account_links
SET end_user_id = $1
WHERE environment_id = $2
  AND id = ANY($3::uuid[])
        ",
            )
            .bind(target_end_user_id)
            .bind(environment_id)
            .bind(account_link_ids)
            .execute(&mut **tx)
            .await
        }
    };

    let expected_rows = u64::try_from(account_link_ids.len()).unwrap_or(u64::MAX);
    match result {
        Ok(result) if result.rows_affected() == expected_rows => Ok(()),
        Ok(_) => Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            messages.not_found,
            None,
            Some(request_id),
        )),
        Err(_) => Err(management_internal_error(request_id, messages.failure)),
    }
}
