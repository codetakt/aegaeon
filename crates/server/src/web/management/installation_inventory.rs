//! Explicit installation inventory. Legacy Team routes retain their existing
//! membership adapter; this route requires a selected grant and current SQL
//! authentication, intersected with the existing API key Team/capability ceiling.
use super::{
    error_response,
    http_errors::management_database_error,
    management_db_pool,
    request_support::owned,
    session_support::{get_management_session_id, management_bearer_api_key},
    transactions, AppState, RequestContext,
};
use axum::{
    extract::{rejection::QueryRejection, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InventoryQuery {
    grant_id: Uuid,
    limit: Option<u16>,
    cursor: Option<String>,
}

pub(super) fn routes() -> Router<AppState> {
    Router::new().route(
        "/installations/:installationId/inventory/:resourceKind",
        get(list_inventory),
    )
}

fn failure(status: StatusCode, code: &str, request_id: &str) -> Response {
    error_response(
        status,
        code,
        "Installation inventory request refused",
        None,
        Some(request_id),
    )
}

fn resource_kind(path: &str) -> Option<&'static str> {
    match path {
        "users" => Some("user"),
        "teams" => Some("team"),
        "tenants" => Some("tenant"),
        "environments" => Some("environment"),
        "organizations" => Some("organization"),
        _ => None,
    }
}

async fn list_inventory(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path((installation, kind)): Path<(String, String)>,
    headers: HeaderMap,
    query: Result<Query<InventoryQuery>, QueryRejection>,
) -> Response {
    let request_id = context.request_id.as_str();
    let (Ok(installation), Some(kind), Ok(Query(query))) =
        (Uuid::parse_str(&installation), resource_kind(&kind), query)
    else {
        return failure(StatusCode::BAD_REQUEST, "invalid_request", request_id);
    };
    let limit = query.limit.unwrap_or(100);
    if installation.is_nil()
        || query.grant_id.is_nil()
        || !(1..=200).contains(&limit)
        || query
            .cursor
            .as_ref()
            .is_some_and(|value| value.len() > 4096)
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_request", request_id);
    }
    let pool = match management_db_pool(&state, request_id) {
        Ok(pool) => pool,
        Err(response) => return response,
    };
    // Initial authentication rejects conflicting header modes and malformed
    // credentials. The SQL entrypoint rechecks the actual credential and grant
    // together; this preliminary result is never the inventory authority.
    let session = match super::require_management_session_async(&state, &headers, request_id).await
    {
        Ok(session) => session,
        Err(response) => return response,
    };
    let credential = if let Some(id) = session.api_key_id() {
        match management_bearer_api_key(&headers, request_id) {
            Ok(Some(raw)) => json!({
                "kind": "SERVICE", "id": id,
                "digest": aegaeon_crypto::hash::sha256_hex(raw.as_bytes()),
            }),
            Ok(None) => return failure(StatusCode::UNAUTHORIZED, "unauthenticated", request_id),
            Err(response) => return response,
        }
    } else {
        match get_management_session_id(&headers, request_id) {
            Ok(Some(sid)) => match state.management.sessions.inventory_credential(&sid) {
                Some(value) => value,
                None => return owned::unavailable(request_id),
            },
            Ok(None) => return failure(StatusCode::UNAUTHORIZED, "unauthenticated", request_id),
            Err(response) => return response,
        }
    };
    let payload = json!({
        "installation_id": installation, "grant_id": query.grant_id,
        "resource_kind": kind, "limit": limit, "cursor": query.cursor,
        "credential": credential,
    });
    let mut connection = match transactions::connection(pool, request_id).await {
        Ok(connection) => connection,
        Err(response) => return response,
    };
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut transaction =
            transactions::begin_management_transaction(&mut connection, request_id).await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(|error| storage_error(&error, request_id))?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *transaction)
            .await
            .map_err(|error| storage_error(&error, request_id))?;
        let value = sqlx::query_scalar::<_, Value>("SELECT management_authority.inventory_v1($1)")
            .bind(payload)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| storage_error(&error, request_id))?;
        transactions::commit_management_transaction(transaction, request_id).await?;
        Ok(value)
    })
    .await
    .unwrap_or_else(|_| {
        let mut response = failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            request_id,
        );
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("1"));
        Err(response)
    });
    match transactions::finish(result, connection, request_id).await {
        Ok(body) => {
            let mut response = (StatusCode::OK, Json(body)).into_response();
            crate::util::apply_no_cache_headers(&mut response);
            super::http_errors::insert_request_id_header(response.headers_mut(), request_id);
            response
        }
        Err(response) => response,
    }
}

fn storage_error(error: &sqlx::Error, request_id: &str) -> Response {
    let code = error.as_database_error().and_then(|error| error.code());
    match code.as_deref() {
        // Only the entrypoint's explicit refusals represent caller authority.
        // PostgreSQL ACL/role failures remain storage errors, never a false 403.
        Some("PMA01") => failure(StatusCode::UNAUTHORIZED, "unauthenticated", request_id),
        Some("PMA02") => failure(StatusCode::FORBIDDEN, "forbidden", request_id),
        Some("22023" | "22P02" | "22007" | "22008" | "22021") => {
            failure(StatusCode::BAD_REQUEST, "invalid_request", request_id)
        }
        _ => management_database_error(request_id, error, "Installation inventory unavailable"),
    }
}
