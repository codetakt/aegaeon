use axum::response::Response;

use super::common::{
    parse_bounded_query_pairs, parse_optional_usize_parameter, push_limited_value,
    MAX_FEDERATION_ENTITY_TYPE_BYTES, MAX_FEDERATION_LIST_PARAM_BYTES,
    MAX_FEDERATION_LIST_PARAM_VALUES,
};
use super::cursor::parse_optional_federation_list_cursor;

const FEDERATION_LIST_DEFAULT_LIMIT: usize = 200;
const FEDERATION_LIST_MAX_LIMIT: usize = 1000;

#[derive(Default)]
pub(in crate::web::openid_federation) struct FederationListQuery {
    entity_type: Vec<String>,
    trust_marked: Vec<String>,
    trust_mark_type: Vec<String>,
    intermediate: Vec<String>,
    cursor: Vec<String>,
    limit: Vec<String>,
    unsupported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::web::openid_federation) struct FederationListPagination {
    pub(in crate::web::openid_federation) cursor: Option<String>,
    pub(in crate::web::openid_federation) limit: usize,
}

impl FederationListQuery {
    pub(in crate::web::openid_federation) fn from_raw_query(
        raw_query: Option<&str>,
        issuer: &str,
    ) -> Result<Self, Response> {
        parse_bounded_query_pairs(raw_query, "federation list", issuer)?
            .into_iter()
            .try_fold(Self::default(), |mut params, (key, value)| {
                match key.as_str() {
                    "entity_type" => push_limited_value(
                        &mut params.entity_type,
                        value,
                        "entity_type",
                        MAX_FEDERATION_ENTITY_TYPE_BYTES,
                        Some(MAX_FEDERATION_LIST_PARAM_VALUES),
                        issuer,
                    )?,
                    "trust_marked" => push_limited_value(
                        &mut params.trust_marked,
                        value,
                        "trust_marked",
                        MAX_FEDERATION_LIST_PARAM_BYTES,
                        Some(MAX_FEDERATION_LIST_PARAM_VALUES),
                        issuer,
                    )?,
                    "trust_mark_type" => push_limited_value(
                        &mut params.trust_mark_type,
                        value,
                        "trust_mark_type",
                        MAX_FEDERATION_LIST_PARAM_BYTES,
                        Some(MAX_FEDERATION_LIST_PARAM_VALUES),
                        issuer,
                    )?,
                    "intermediate" => push_limited_value(
                        &mut params.intermediate,
                        value,
                        "intermediate",
                        MAX_FEDERATION_LIST_PARAM_BYTES,
                        Some(MAX_FEDERATION_LIST_PARAM_VALUES),
                        issuer,
                    )?,
                    "cursor" => push_limited_value(
                        &mut params.cursor,
                        value,
                        "cursor",
                        super::common::MAX_FEDERATION_LIST_CURSOR_BYTES,
                        Some(1),
                        issuer,
                    )?,
                    "limit" => push_limited_value(
                        &mut params.limit,
                        value,
                        "limit",
                        MAX_FEDERATION_LIST_PARAM_BYTES,
                        Some(1),
                        issuer,
                    )?,
                    _ => params.unsupported.push(key),
                }
                Ok(params)
            })
    }

    pub(in crate::web::openid_federation) fn pagination(
        &self,
        issuer: &str,
    ) -> Result<FederationListPagination, Response> {
        Ok(FederationListPagination {
            cursor: parse_optional_federation_list_cursor(&self.cursor, issuer)?,
            limit: parse_optional_usize_parameter(
                &self.limit,
                "limit",
                FEDERATION_LIST_DEFAULT_LIMIT,
                Some(1..=FEDERATION_LIST_MAX_LIMIT),
                issuer,
            )?,
        })
    }
}

#[cfg(test)]
pub(in crate::web) fn federation_list_pagination_for_tests(
    raw_query: Option<&str>,
    issuer: &str,
) -> Result<(Option<String>, usize), Response> {
    FederationListQuery::from_raw_query(raw_query, issuer)?
        .pagination(issuer)
        .map(|pagination| (pagination.cursor, pagination.limit))
}
