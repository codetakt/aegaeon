use super::super::parser::ParsedCsvUserRow;
use crate::local_credentials::{self, RecoveryTokenPurpose};
use crate::management::types::{
    ImportUsersCsvRequest, ImportUsersCsvResponse, ImportedUserRow, User,
};
use crate::organizations::witness::creation::{primary, Receipt};
use crate::web::management::{
    error_response, management_internal_error, request_support::creation,
    write_user_management_audit_event, EndUserAuditEvent, UserManagementContext,
};
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use sqlx::{Postgres, Transaction};
mod binding;
mod row;

pub(super) async fn import(
    context: &UserManagementContext,
    body: &ImportUsersCsvRequest,
    headers: &HeaderMap,
    rows: &[ParsedCsvUserRow],
    request_id: &str,
) -> Result<ImportUsersCsvResponse, Response> {
    let inputs = binding::inputs(context, body, headers, rows, request_id)?;
    creation::execute_batch(
        context,
        &inputs,
        &Import {
            context,
            body,
            rows,
            request_id,
        },
        request_id,
    )
    .await
}

struct Import<'a> {
    context: &'a UserManagementContext,
    body: &'a ImportUsersCsvRequest,
    rows: &'a [ParsedCsvUserRow],
    request_id: &'a str,
}
impl primary::batch::Mutation for Import<'_> {
    type Output = ImportUsersCsvResponse;
    type Error = Response;
    fn apply<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipts: &'a [Receipt],
    ) -> primary::MutationFuture<'a, Self::Output, Response> {
        Box::pin(async move {
            self.context
                .require_lifecycle_role_in_transaction(tx, self.request_id)
                .await?;
            let (issuer, ttl) = self.current_policy(tx).await?;
            let mut imported_users = Vec::with_capacity(receipts.len());
            for (receipt, row) in receipts.iter().zip(self.rows) {
                imported_users.push(self.insert(tx, receipt, row, &issuer, ttl).await?);
            }
            Ok(ImportUsersCsvResponse { imported_users })
        })
    }
    fn replay<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipts: &'a [Receipt],
    ) -> primary::MutationFuture<'a, Self::Output, Response> {
        Box::pin(async move {
            self.context
                .require_lifecycle_role_in_transaction(tx, self.request_id)
                .await?;
            let mut imported_users = Vec::with_capacity(receipts.len());
            for (receipt, row) in receipts.iter().zip(self.rows) {
                imported_users.push(ImportedUserRow {
                    row_number: row.row_number,
                    user: self.current(tx, receipt).await?,
                    activation: None,
                });
            }
            if self.body.issue_activation_tokens {
                return Err(error_response(
                    StatusCode::CONFLICT,
                    "one_time_result_unavailable",
                    "CSV import already committed; use explicit activation issuance if needed",
                    None,
                    Some(self.request_id),
                ));
            }
            Ok(ImportUsersCsvResponse { imported_users })
        })
    }
}
impl Import<'_> {
    async fn current_policy(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(String, Option<i64>), Response> {
        let issuer = sqlx::query_scalar("SELECT e.issuer_url FROM aegaeon.environments e JOIN aegaeon.tenants t ON t.id=e.tenant_id WHERE e.id=$1 AND t.team_id=$2 AND e.status<>'DELETED' AND t.status<>'DELETED' FOR SHARE OF e,t")
            .bind(self.context.environment_id).bind(self.context.team_id).fetch_one(&mut **tx).await
            .map_err(|_| management_internal_error(self.request_id,"Failed to load current issuer"))?;
        if !self.body.issue_activation_tokens {
            return Ok((issuer, None));
        }
        sqlx::query("SELECT environment_id FROM aegaeon.environment_policies WHERE environment_id=$1 FOR SHARE")
            .bind(self.context.environment_id).fetch_one(&mut **tx).await
            .map_err(|_| management_internal_error(self.request_id,"Failed to lock current recovery policy"))?;
        let policy = crate::web::management::user_credentials::policy::load_recovery_token_ttl_policy_in_transaction(tx,self.context.environment_id,self.request_id).await?;
        let ttl = local_credentials::sanitize_recovery_token_ttl(
            self.body.activation_token_expires_in_seconds,
            RecoveryTokenPurpose::Activation,
            policy,
        )
        .map_err(|message| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                message,
                None,
                Some(self.request_id),
            )
        })?;
        Ok((issuer, Some(ttl)))
    }
    async fn current(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        receipt: &Receipt,
    ) -> Result<User, Response> {
        crate::web::management::users::store::load_user_row_for_status(
            &mut **tx,
            self.context,
            receipt.owner_id(),
            "AND u.status <> 'DELETED'",
            "User not found",
            self.request_id,
        )
        .await
    }
}
