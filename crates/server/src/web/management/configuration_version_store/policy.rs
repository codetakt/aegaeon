mod query;

use axum::{http::StatusCode, response::Response};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::management::types::PolicyDocument;

use super::super::configuration_policy_rows::policy_document_from_environment_policy_row;
use super::super::{error_response, management_internal_error};

pub(in crate::web::management) async fn load_environment_policy_document(
    pool: &PgPool,
    environment_id: Uuid,
    request_id: &str,
) -> Result<PolicyDocument, Response> {
    let row = sqlx::query(query::SELECT_ENVIRONMENT_POLICY_SQL)
        .bind(environment_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    let Some(row) = row else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Policies not found",
            None,
            Some(request_id),
        ));
    };

    policy_document_from_environment_policy_row(&row, request_id)
}

pub(in crate::web::management) async fn load_environment_policy_document_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    request_id: &str,
) -> Result<PolicyDocument, Response> {
    let row = sqlx::query(query::SELECT_ENVIRONMENT_POLICY_SQL)
        .bind(environment_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    let Some(row) = row else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Policies not found",
            None,
            Some(request_id),
        ));
    };

    policy_document_from_environment_policy_row(&row, request_id)
}
