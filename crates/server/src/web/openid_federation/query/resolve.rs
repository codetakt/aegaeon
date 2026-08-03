use axum::{http::StatusCode, response::Response};

use super::super::support::{
    federation_error_response, unsupported_federation_query_parameter_response,
};
use super::common::{
    parse_bounded_query_pairs, push_limited_value, validate_federation_entity_id_parameter,
    validate_federation_entity_type_parameters, MAX_FEDERATION_ENTITY_ID_BYTES,
    MAX_FEDERATION_ENTITY_TYPE_BYTES, MAX_RESOLVE_ENTITY_TYPES, MAX_RESOLVE_TRUST_ANCHORS,
};
use crate::web::oauth_errors::json_error_with_iss;

#[derive(Default)]
pub(in crate::web) struct FederationResolveQuery {
    pub(in crate::web) sub: Vec<String>,
    pub(in crate::web) trust_anchor: Vec<String>,
    pub(in crate::web) entity_type: Vec<String>,
    pub(in crate::web) anchor: Vec<String>,
    pub(in crate::web) unsupported: Vec<String>,
}

pub(in crate::web) struct ValidFederationResolveQuery {
    pub(in crate::web) sub: String,
    pub(in crate::web) trust_anchors: Vec<String>,
    pub(in crate::web) entity_types: Vec<String>,
}

impl FederationResolveQuery {
    pub(in crate::web) fn from_raw_query(
        raw_query: Option<&str>,
        issuer: &str,
    ) -> Result<Self, Response> {
        parse_bounded_query_pairs(raw_query, "federation resolve", issuer)?
            .into_iter()
            .try_fold(Self::default(), |mut params, (key, value)| {
                params.push_bounded_pair(key, value, issuer)?;
                Ok(params)
            })
    }

    fn push_bounded_pair(
        &mut self,
        key: String,
        value: String,
        issuer: &str,
    ) -> Result<(), Response> {
        match key.as_str() {
            "sub" => push_limited_value(
                &mut self.sub,
                value,
                "sub",
                MAX_FEDERATION_ENTITY_ID_BYTES,
                None,
                issuer,
            )?,
            "trust_anchor" => push_limited_value(
                &mut self.trust_anchor,
                value,
                "trust_anchor",
                MAX_FEDERATION_ENTITY_ID_BYTES,
                Some(MAX_RESOLVE_TRUST_ANCHORS),
                issuer,
            )?,
            "entity_type" => push_limited_value(
                &mut self.entity_type,
                value,
                "entity_type",
                MAX_FEDERATION_ENTITY_TYPE_BYTES,
                Some(MAX_RESOLVE_ENTITY_TYPES),
                issuer,
            )?,
            "anchor" => push_limited_value(
                &mut self.anchor,
                value,
                "anchor",
                MAX_FEDERATION_ENTITY_ID_BYTES,
                Some(MAX_RESOLVE_TRUST_ANCHORS),
                issuer,
            )?,
            _ => self.unsupported.push(key),
        }
        Ok(())
    }

    fn unsupported_parameter(&self) -> Option<&str> {
        if !self.anchor.is_empty() {
            Some("anchor")
        } else {
            self.unsupported.first().map(String::as_str)
        }
    }
}

pub(in crate::web) fn validate_federation_resolve_query(
    params: FederationResolveQuery,
    issuer: &str,
) -> Result<ValidFederationResolveQuery, Response> {
    if let Some(parameter) = params.unsupported_parameter() {
        if parameter != "anchor" {
            return Err(unsupported_federation_query_parameter_response(
                parameter, issuer,
            ));
        }
        return Err(federation_error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_parameter",
            match parameter {
                "anchor" => {
                    "anchor is not supported by this federation resolve endpoint; use trust_anchor"
                }
                _ => "unsupported federation resolve query parameter",
            },
            issuer,
        ));
    }

    let sub = match params.sub.as_slice() {
        [sub] => validate_federation_entity_id_parameter("sub", sub, issuer)?,
        [] => {
            return Err(json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("missing required 'sub' query parameter"),
                issuer,
            ));
        }
        _ => {
            return Err(json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("'sub' query parameter must appear exactly once"),
                issuer,
            ));
        }
    };

    if params.trust_anchor.is_empty() {
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("missing required 'trust_anchor' query parameter"),
            issuer,
        ));
    }
    let trust_anchors = params
        .trust_anchor
        .iter()
        .map(|anchor| validate_federation_entity_id_parameter("trust_anchor", anchor, issuer))
        .collect::<Result<Vec<_>, _>>()?;
    let entity_types = validate_federation_entity_type_parameters(params.entity_type, issuer)?;

    Ok(ValidFederationResolveQuery {
        sub,
        trust_anchors,
        entity_types,
    })
}
