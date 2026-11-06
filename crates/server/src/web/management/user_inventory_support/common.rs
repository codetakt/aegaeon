use crate::util;
use crate::web::management::error_response;
use axum::{http::StatusCode, response::Response};
use std::time::SystemTime;

pub(in crate::web::management::user_inventory_support) fn inventory_fingerprint(
    raw: &str,
) -> String {
    aegaeon_crypto::hash::sha256_hex(raw.as_bytes())
}

pub(in crate::web::management::user_inventory_support) fn seconds_since_epoch(
    value: SystemTime,
) -> Option<i64> {
    util::unix_epoch_secs_i64(value)
        .inspect_err(|err| {
            util::log_clock_error("management stored timestamp", err);
        })
        .ok()
}

pub(in crate::web::management) fn user_runtime_store_error_response(
    store: &str,
    error: &str,
    description: &str,
    request_id: &str,
) -> Response {
    tracing::error!(
        store,
        error,
        request_id,
        "user runtime store operation failed"
    );
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        description,
        None,
        Some(request_id),
    )
}

pub(super) async fn token_inventory_page(
    state: &crate::web::AppState,
    subject: &str,
    kind: crate::authcode::store::TokenInventoryKind,
    query: &crate::web::management::PaginationQuery,
    request_id: &str,
) -> Result<
    (
        Vec<crate::authcode::store::TokenInventoryRecord>,
        Option<crate::management::types::PageInfo>,
    ),
    Response,
> {
    use crate::authcode::store::TokenInventoryCursor;
    use crate::web::management::pagination::{
        encode_keyset_page_token, invalid_page_token_response, pagination_params,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let params = pagination_params(query, 3, request_id)?;
    let decode = |value: &str| {
        URL_SAFE_NO_PAD
            .decode(value)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| invalid_page_token_response(request_id))
    };
    let cursor = match (
        params.cursor_value(0),
        params.cursor_value(1),
        params.cursor_value(2),
    ) {
        (None, None, None) => None,
        (Some(group), Some(token), Some(emitted)) => Some(TokenInventoryCursor {
            group: decode(group)?,
            token: decode(token)?,
            group_emitted: match emitted {
                "0" => false,
                "1" => true,
                _ => return Err(invalid_page_token_response(request_id)),
            },
        }),
        _ => return Err(invalid_page_token_response(request_id)),
    };
    let page = state
        .tokens
        .store
        .inventory_page(
            subject,
            kind,
            cursor,
            usize::try_from(params.limit).map_err(|_| invalid_page_token_response(request_id))?,
        )
        .await
        .map_err(|error| {
            user_runtime_store_error_response(
                "token store",
                &error,
                "Token inventory store unavailable",
                request_id,
            )
        })?;
    let info = page.next.map(|c| crate::management::types::PageInfo {
        next_page_token: Some(encode_keyset_page_token([
            URL_SAFE_NO_PAD.encode(c.group),
            URL_SAFE_NO_PAD.encode(c.token),
            if c.group_emitted {
                "1".into()
            } else {
                "0".into()
            },
        ])),
    });
    Ok((page.records, info))
}
