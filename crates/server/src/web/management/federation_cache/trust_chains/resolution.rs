use super::super::super::{federation_management_error_response, management_internal_error};
use super::super::time::unix_epoch_now_i64;
use crate::federation::{verify_signed_path, FederationError, TrustAnchor};
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

pub(in crate::web::management) async fn resolve_refreshed_trust_chain_payload<F, Fut>(
    existing: &FederationTrustChainEntry,
    trust_anchors: Vec<TrustAnchor>,
    request_id: &str,
    acquire: F,
) -> Result<serde_json::Value, Response>
where
    F: FnOnce(String, Vec<TrustAnchor>, i64) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<String>, FederationError>>,
{
    let now_epoch = unix_epoch_now_i64(request_id)?;
    let leaf_entity_id = existing.leaf_entity_id.clone();
    let anchor = trust_anchors
        .iter()
        .find(|anchor| anchor.entity_id == existing.anchor_entity_id)
        .cloned()
        .ok_or_else(|| {
            federation_management_error_response(
                FederationError::ChainResolution("cached trust anchor is not configured".into()),
                request_id,
            )
        })?;
    let raw = acquire(leaf_entity_id.clone(), trust_anchors, now_epoch)
        .await
        .map_err(|error| federation_management_error_response(error, request_id))?;
    // Acquisition cannot vouch for a typed chain. Reverify retained signed
    // bytes, exact expected leaf/anchor and policies before any refresh write.
    verify_signed_path(&raw, &leaf_entity_id, &anchor, now_epoch)
        .map_err(|error| federation_management_error_response(error, request_id))?;
    serialize_trust_chain_payload(&raw, request_id)
}
