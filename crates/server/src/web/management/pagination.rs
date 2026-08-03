use axum::{http::StatusCode, response::Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Row};

use crate::management::types::PageInfo;

use super::{error_response, management_internal_error, PaginationQuery};

pub(super) const DEFAULT_PAGE_SIZE: u32 = 50;
pub(super) const MAX_PAGE_SIZE: u32 = 200;
const MAX_PAGE_TOKEN_BYTES: usize = 2048;
const PAGE_TOKEN_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::web::management) struct KeysetPagination {
    pub(in crate::web::management) limit: i64,
    cursor_values: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeysetPageToken {
    v: u8,
    values: Vec<String>,
}

impl KeysetPagination {
    pub(in crate::web::management) fn cursor_value(&self, index: usize) -> Option<&str> {
        self.cursor_values
            .as_ref()
            .and_then(|values| values.get(index))
            .map(String::as_str)
    }
}

pub(super) fn decode_keyset_page_token(token: &str, expected_values: usize) -> Option<Vec<String>> {
    if token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    let parsed: KeysetPageToken = serde_json::from_slice(&decoded).ok()?;
    (parsed.v == PAGE_TOKEN_VERSION
        && parsed.values.len() == expected_values
        && parsed.values.iter().all(|value| !value.is_empty()))
    .then_some(parsed.values)
}

pub(super) fn encode_keyset_page_token(values: impl IntoIterator<Item = String>) -> String {
    let token = KeysetPageToken {
        v: PAGE_TOKEN_VERSION,
        values: values.into_iter().collect(),
    };
    let bytes = serde_json::to_vec(&token).unwrap_or_else(|_| b"{\"v\":1,\"values\":[]}".to_vec());
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(super) fn invalid_page_token_response(request_id: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "pageToken is invalid",
        None,
        Some(request_id),
    )
}

pub(super) fn pagination_params(
    query: &PaginationQuery,
    expected_cursor_values: usize,
    request_id: &str,
) -> Result<KeysetPagination, Response> {
    let page_size = query
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    let cursor_values = match query.page_token.as_deref() {
        Some(token) => Some(
            decode_keyset_page_token(token, expected_cursor_values)
                .ok_or_else(|| invalid_page_token_response(request_id))?,
        ),
        None => None,
    };
    Ok(KeysetPagination {
        limit: i64::from(page_size),
        cursor_values,
    })
}

pub(super) fn timestamp_uuid_pagination_params(
    query: &PaginationQuery,
    request_id: &str,
) -> Result<KeysetPagination, Response> {
    let pagination = pagination_params(query, 2, request_id)?;
    validate_cursor_pair(
        &pagination,
        request_id,
        super::audit_time::is_valid_iso8601,
        |value| uuid::Uuid::parse_str(value).is_ok(),
    )?;
    Ok(pagination)
}

pub(super) fn integer_uuid_pagination_params(
    query: &PaginationQuery,
    request_id: &str,
) -> Result<KeysetPagination, Response> {
    let pagination = pagination_params(query, 2, request_id)?;
    validate_cursor_pair(
        &pagination,
        request_id,
        |value| value.parse::<i64>().is_ok(),
        |value| uuid::Uuid::parse_str(value).is_ok(),
    )?;
    Ok(pagination)
}

fn validate_cursor_pair(
    pagination: &KeysetPagination,
    request_id: &str,
    first_valid: impl FnOnce(&str) -> bool,
    second_valid: impl FnOnce(&str) -> bool,
) -> Result<(), Response> {
    match (pagination.cursor_value(0), pagination.cursor_value(1)) {
        (Some(first), Some(second)) if first_valid(first) && second_valid(second) => Ok(()),
        (Some(_), Some(_)) => Err(invalid_page_token_response(request_id)),
        (None, None) => Ok(()),
        _ => Err(invalid_page_token_response(request_id)),
    }
}

pub(super) fn nonnegative_i64_to_usize(value: i64) -> usize {
    usize::try_from(value.max(0)).ok().unwrap_or(usize::MAX)
}

pub(super) fn pagination_limit(limit: i64) -> usize {
    usize::try_from(limit).unwrap_or(usize::try_from(MAX_PAGE_SIZE).unwrap_or(200))
}

pub(super) fn page_info_for_keyset_rows<F>(
    rows: &[PgRow],
    limit: i64,
    cursor_from_row: F,
) -> Result<Option<PageInfo>, Response>
where
    F: FnOnce(&PgRow) -> Result<Vec<String>, Response>,
{
    let limit_usize = pagination_limit(limit);
    if rows.len() <= limit_usize {
        return Ok(None);
    }

    rows.iter()
        .take(limit_usize)
        .last()
        .map(cursor_from_row)
        .transpose()
        .map(|cursor| {
            cursor.map(|values| PageInfo {
                next_page_token: Some(encode_keyset_page_token(values)),
            })
        })
}

pub(super) fn keyset_cursor_from_row(
    row: &PgRow,
    columns: &[&'static str],
    request_id: &str,
) -> Result<Vec<String>, Response> {
    columns
        .iter()
        .map(|column| {
            row.try_get::<String, _>(*column)
                .map_err(|_| management_internal_error(request_id, "Database row decode failed"))
        })
        .collect()
}

pub(super) fn collect_page_rows_result<T, F>(
    rows: &[PgRow],
    limit: i64,
    row_mapper: F,
) -> Result<Vec<T>, Response>
where
    F: FnMut(&PgRow) -> Result<T, Response>,
{
    rows.iter()
        .take(pagination_limit(limit))
        .map(row_mapper)
        .collect()
}

pub(super) fn paginate_in_memory<T>(
    items: Vec<T>,
    query: &PaginationQuery,
    request_id: &str,
) -> Result<(Vec<T>, Option<PageInfo>), Response> {
    let page_size = query
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE) as usize;
    let offset = match query.page_token.as_deref() {
        Some(token) => decode_keyset_page_token(token, 1)
            .and_then(|values| values.into_iter().next())
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|offset| *offset <= items.len())
            .ok_or_else(|| invalid_page_token_response(request_id))?,
        None => 0,
    };
    let end = offset.saturating_add(page_size).min(items.len());
    let page_info = (end < items.len()).then(|| PageInfo {
        next_page_token: Some(encode_keyset_page_token([end.to_string()])),
    });
    Ok((
        items.into_iter().skip(offset).take(page_size).collect(),
        page_info,
    ))
}
