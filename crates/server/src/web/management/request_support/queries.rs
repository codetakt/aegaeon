use axum::response::Response;
use serde::Deserialize;

use super::super::pagination::timestamp_uuid_pagination_params;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::web::management) struct PaginationQuery {
    pub(in crate::web::management) page_size: Option<u32>,
    pub(in crate::web::management) page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::web::management) struct AccountLinkListQuery {
    pub(in crate::web::management) page_size: Option<u32>,
    pub(in crate::web::management) page_token: Option<String>,
    pub(in crate::web::management) upstream_issuer: Option<String>,
    pub(in crate::web::management) upstream_subject: Option<String>,
    pub(in crate::web::management) end_user_subject: Option<String>,
    pub(in crate::web::management) end_user_email: Option<String>,
    pub(in crate::web::management) connection_identifier: Option<String>,
}

pub(in crate::web::management) fn pagination_params_from_parts(
    page_size: Option<u32>,
    page_token: Option<String>,
    request_id: &str,
) -> Result<super::super::pagination::KeysetPagination, Response> {
    timestamp_uuid_pagination_params(
        &PaginationQuery {
            page_size,
            page_token,
        },
        request_id,
    )
}
