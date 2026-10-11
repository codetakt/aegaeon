use serde_json::Value;

use crate::federation::{
    admit_entity_configuration, EntityStatement, FederationError, TrustAnchor, TrustChain,
};

use super::super::types::{StoredEntityCache, StoredTrustChain};

pub(super) fn reconstruct_entity_configuration_from_cache(
    cached: &StoredEntityCache,
    expected_entity_id: &str,
    now: i64,
) -> Result<EntityStatement, FederationError> {
    admit_entity_configuration(&cached.entity_configuration_jws, expected_entity_id, now)
}

pub(in crate::federation) fn reconstruct_chain_from_cache(
    cached: &StoredTrustChain,
    anchor: &TrustAnchor,
    now: i64,
) -> Result<TrustChain, FederationError> {
    if cached.anchor_entity_id != anchor.entity_id {
        return Err(FederationError::Validation(
            "cached chain anchor does not match cache key".into(),
        ));
    }
    let jwts = cached_chain_jwts_owned(&cached.chain_jwts)?;
    crate::federation::trust_chain::verify_signed_path(&jwts, &cached.leaf_entity_id, anchor, now)
}

fn cached_chain_jwts(chain_jwts: &Value) -> Result<Vec<&str>, FederationError> {
    chain_jwts
        .as_array()
        .ok_or_else(|| FederationError::Validation("cached chain is not an array".into()))?
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                FederationError::Validation(
                    "cached chain_jwts must contain compact JWS strings".into(),
                )
            })
        })
        .collect()
}

pub(super) fn cached_chain_jwts_owned(chain_jwts: &Value) -> Result<Vec<String>, FederationError> {
    cached_chain_jwts(chain_jwts).map(|jwts| jwts.into_iter().map(str::to_string).collect())
}

pub(super) fn chain_jwts_to_value(chain_jwts: &[String]) -> Value {
    Value::Array(chain_jwts.iter().cloned().map(Value::String).collect())
}
