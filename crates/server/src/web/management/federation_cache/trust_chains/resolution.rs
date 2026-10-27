use super::super::super::federation_management_error_response;
use super::super::time::unix_epoch_now_i64;
use crate::federation::{verify_signed_path, FederationError, TrustAnchor};
use crate::management::types::FederationTrustChainEntry;
use axum::response::Response;

pub(in crate::web::management) async fn resolve_refreshed_trust_chain_payload<F, Fut>(
    existing: &FederationTrustChainEntry,
    trust_anchors: Vec<TrustAnchor>,
    request_id: &str,
    acquire: F,
) -> Result<Vec<String>, Response>
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
    let raw = acquire(leaf_entity_id.clone(), vec![anchor.clone()], now_epoch)
        .await
        .map_err(|error| federation_management_error_response(error, request_id))?;
    // Acquisition cannot vouch for a typed chain. Reverify retained signed
    // bytes, exact expected leaf/anchor and policies before any refresh write.
    verify_signed_path(&raw, &leaf_entity_id, &anchor, now_epoch)
        .map_err(|error| federation_management_error_response(error, request_id))?;
    Ok(raw)
}

// Called while the configured anchor rows are locked through renewal/audit.
pub(in crate::web::management) fn validate_refreshed_trust_chain(
    raw: &[String],
    existing: &FederationTrustChainEntry,
    trust_anchors: &[TrustAnchor],
    request_id: &str,
) -> Result<(), Response> {
    let anchor = trust_anchors
        .iter()
        .find(|anchor| anchor.entity_id == existing.anchor_entity_id)
        .ok_or_else(|| {
            federation_management_error_response(
                FederationError::ChainResolution(
                    "cached trust anchor is no longer configured".into(),
                ),
                request_id,
            )
        })?;
    verify_signed_path(
        raw,
        &existing.leaf_entity_id,
        anchor,
        unix_epoch_now_i64(request_id)?,
    )
    .map_err(|error| federation_management_error_response(error, request_id))?;
    Ok(())
}
