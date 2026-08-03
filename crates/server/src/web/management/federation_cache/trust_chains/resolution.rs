use super::super::super::{federation_management_error_response, management_internal_error};
use super::super::time::unix_epoch_now_i64;
use crate::federation::{
    resolve_trust_chain_with_jwts, FederationError, HttpFederationFetcher, TrustAnchor,
};
use crate::management::types::FederationTrustChainEntry;
use axum::response::Response;

fn serialize_trust_chain_payload(
    chain_jwts: &[String],
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    if chain_jwts.iter().any(|jws| jws.trim().is_empty()) {
        return Err(management_internal_error(
            request_id,
            "Resolved federation trust chain included an empty compact JWS",
        ));
    }

    Ok(serde_json::Value::Array(
        chain_jwts
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect(),
    ))
}

pub(in crate::web::management) async fn resolve_refreshed_trust_chain_payload(
    existing: &FederationTrustChainEntry,
    trust_anchors: Vec<TrustAnchor>,
    outbound_allowed_domains: Vec<String>,
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    let now_epoch = unix_epoch_now_i64(request_id)?;
    let leaf_entity_id = existing.leaf_entity_id.clone();
    let expected_anchor_entity_id = existing.anchor_entity_id.clone();
    let fetcher =
        HttpFederationFetcher::try_with_optional_allowed_domains(&outbound_allowed_domains)
            .map_err(|error| federation_management_error_response(error, request_id))?;
    let resolved =
        resolve_trust_chain_with_jwts(&leaf_entity_id, &trust_anchors, &fetcher, now_epoch)
            .await
            .map_err(|error| federation_management_error_response(error, request_id))?;

    if resolved.trust_chain.anchor.entity_id != expected_anchor_entity_id {
        return Err(federation_management_error_response(
            FederationError::ChainResolution(format!(
                "resolved trust anchor '{}' does not match cached anchor '{}'",
                resolved.trust_chain.anchor.entity_id, expected_anchor_entity_id
            )),
            request_id,
        ));
    }

    serialize_trust_chain_payload(&resolved.chain_jwts, request_id)
}
