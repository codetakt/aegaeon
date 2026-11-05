//! Keep SQL errors separate from admission/cleanup errors at the HTTP boundary.
use super::{connection, scoped, unavailable};
use axum::response::Response;
use sqlx::{
    postgres::{PgArguments, PgRow},
    query::Query,
    PgPool, Postgres,
};

pub(in crate::web::management) async fn all(
    pool: &PgPool,
    query: Query<'_, Postgres, PgArguments>,
    request_id: &str,
) -> Result<Result<Vec<PgRow>, sqlx::Error>, Response> {
    let mut connection = connection(pool)
        .await
        .map_err(|_| unavailable(request_id))?;
    let result = query
        .fetch_all(connection.as_mut().map_err(|_| unavailable(request_id))?)
        .await;
    connection.release().await;
    scoped().map_err(|_| unavailable(request_id))?;
    Ok(result)
}

pub(in crate::web::management) async fn optional(
    pool: &PgPool,
    query: Query<'_, Postgres, PgArguments>,
    request_id: &str,
) -> Result<Result<Option<PgRow>, sqlx::Error>, Response> {
    let mut connection = connection(pool)
        .await
        .map_err(|_| unavailable(request_id))?;
    let result = query
        .fetch_optional(connection.as_mut().map_err(|_| unavailable(request_id))?)
        .await;
    connection.release().await;
    scoped().map_err(|_| unavailable(request_id))?;
    Ok(result)
}

#[cfg(test)]
mod tests;
