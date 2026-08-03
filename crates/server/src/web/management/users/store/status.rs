mod query;

use super::super::super::{
    error_response, management_internal_error, user_from_row_result, UserManagementContext,
};
use crate::management::types::User;
use axum::{http::StatusCode, response::Response};
use sqlx::{Executor, Postgres};
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(in crate::web::management::users) struct UserStatusUpdateMessages {
    pub(in crate::web::management::users) not_found_message: &'static str,
    pub(in crate::web::management::users) failure_message: &'static str,
}

pub(in crate::web::management::users) async fn load_user_row_for_status<'e, E>(
    executor: E,
    context: &UserManagementContext,
    user_id: Uuid,
    status_filter_sql: &str,
    not_found_message: &str,
    request_id: &str,
) -> Result<User, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    let sql = query::load_user_for_status_sql(status_filter_sql);
    let row = sqlx::query(&sql)
        .bind(user_id)
        .bind(context.environment_id)
        .bind(context.team_id)
        .fetch_optional(executor)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))?;
    let row = row.ok_or_else(|| {
        error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            not_found_message,
            None,
            Some(request_id),
        )
    })?;

    user_from_row_result(&row, request_id)
}

#[cfg(test)]
pub(in crate::web::management) fn load_user_for_status_sql_for_test(
    status_filter_sql: &str,
) -> String {
    query::load_user_for_status_sql(status_filter_sql)
}

#[cfg(test)]
pub(in crate::web::management) fn update_user_status_sql_for_test(
    status_filter_sql: &str,
    set_clause_sql: &str,
) -> String {
    query::update_user_status_sql(status_filter_sql, set_clause_sql)
}

pub(in crate::web::management::users) async fn update_user_status_row<'e, E>(
    executor: E,
    context: &UserManagementContext,
    user_id: Uuid,
    status_filter_sql: &str,
    set_clause_sql: &str,
    messages: UserStatusUpdateMessages,
    request_id: &str,
) -> Result<User, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    let sql = query::update_user_status_sql(status_filter_sql, set_clause_sql);
    let row = sqlx::query(&sql)
        .bind(user_id)
        .bind(context.environment_id)
        .bind(context.team_id)
        .fetch_optional(executor)
        .await
        .map_err(|_| management_internal_error(request_id, messages.failure_message))?;
    let row = row.ok_or_else(|| {
        error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            messages.not_found_message,
            None,
            Some(request_id),
        )
    })?;

    user_from_row_result(&row, request_id)
}
