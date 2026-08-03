use super::super::super::{
    insert_invited_user, write_user_management_audit_event, EndUserAuditEvent,
    UserManagementContext,
};
use super::super::recovery_issuance::issue_recovery_token_with_redeem_url;
use super::super::responses::load_issued_recovery_token_response_required;
use super::parser::ParsedCsvUserRow;
use crate::local_credentials::{self, RecoveryTokenPurpose};
use crate::management::types::{ImportedUserRow, User};
use axum::response::Response;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(super) struct PendingImportedUserRow {
    row_number: i64,
    user_id: Uuid,
    user: User,
    activation: Option<(local_credentials::IssuedRecoveryToken, String)>,
}

pub(super) async fn import_csv_user_row(
    tx: &mut Transaction<'_, Postgres>,
    context: &UserManagementContext,
    row: ParsedCsvUserRow,
    issuer_url: &str,
    activation_ttl: Option<i64>,
    request_id: &str,
) -> Result<PendingImportedUserRow, Response> {
    let duplicate_message = format!(
        "CSV row {} conflicts with an existing subject",
        row.row_number
    );
    let (user_id, user) = insert_invited_user(
        tx,
        context.environment_id,
        &row.subject,
        row.email.as_deref(),
        &duplicate_message,
        request_id,
    )
    .await?;
    let activation = if let Some(ttl) = activation_ttl {
        Some(
            issue_recovery_token_with_redeem_url(
                tx,
                issuer_url,
                user_id,
                RecoveryTokenPurpose::Activation,
                ttl,
                context.session.administrator_id,
                request_id,
            )
            .await?,
        )
    } else {
        None
    };

    write_user_management_audit_event(
        tx,
        context,
        request_id,
        EndUserAuditEvent {
            event_type: "management.user.imported.v1",
            target_id: user_id,
            data: serde_json::json!({
                "rowNumber": row.row_number,
                "userId": &user.id,
                "subject": &user.subject,
                "email": &user.email,
                "status": &user.status,
                "issuedActivation": activation.is_some(),
            }),
        },
    )
    .await?;

    Ok(PendingImportedUserRow {
        row_number: row.row_number,
        user_id,
        user,
        activation,
    })
}

pub(super) async fn imported_user_row_response(
    pool: &PgPool,
    row: PendingImportedUserRow,
    request_id: &str,
) -> Result<ImportedUserRow, Response> {
    let activation = match row.activation {
        Some((issued, redeem_url)) => Some(
            load_issued_recovery_token_response_required(
                pool,
                row.user_id,
                issued,
                redeem_url,
                request_id,
            )
            .await?,
        ),
        None => None,
    };

    Ok(ImportedUserRow {
        row_number: row.row_number,
        user: row.user,
        activation,
    })
}
