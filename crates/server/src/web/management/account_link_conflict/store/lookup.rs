use super::super::super::{
    error_response, load_account_link_summary_by_upstream_subject_for_update,
    ManagementEnvironmentScope,
};
use crate::management::types::AccountLinkSummary;
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};

pub(in crate::web::management::account_link_conflict) async fn load_account_link_conflict_required(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    request_id: &str,
) -> Result<AccountLinkSummary, Response> {
    match load_account_link_summary_by_upstream_subject_for_update(
        tx,
        scope.team,
        scope.environment,
        upstream_issuer,
        upstream_sub_hash,
        request_id,
    )
    .await
    {
        Ok(Some(account_link)) => Ok(account_link),
        Ok(None) => Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Account link conflict not found",
            None,
            Some(request_id),
        )),
        Err(resp) => Err(resp),
    }
}
