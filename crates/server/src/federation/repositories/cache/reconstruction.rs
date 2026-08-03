use serde_json::Value;

use crate::federation::trust_chain::{
    leaf_entity_types, validate_anchor_subordinate_metadata_policy,
    validate_entity_configuration_link, validate_path_constraints,
    validate_subordinate_statement_link,
};
use crate::federation::{
    validate_entity_statement, verify_entity_configuration, verify_entity_statement,
    EntityStatement, FederationError, ResolvedTrustChain, TrustAnchor, TrustChain,
};

use super::super::types::{StoredEntityCache, StoredTrustChain};

pub(super) fn reconstruct_entity_configuration_from_cache(
    cached: &StoredEntityCache,
    expected_entity_id: &str,
    now: i64,
) -> Result<EntityStatement, FederationError> {
    let stmt = verify_entity_configuration(&cached.entity_configuration_jws)?;
    validate_entity_statement(&stmt, now)?;
    validate_entity_configuration_link(&stmt, expected_entity_id)?;
    Ok(stmt)
}

pub(in crate::federation) fn reconstruct_chain_from_cache(
    cached: &StoredTrustChain,
    anchor: &TrustAnchor,
) -> Result<TrustChain, FederationError> {
    let chain_jwts = cached_chain_jwts(&cached.chain_jwts)?;

    let (leaf_jws, rest) = chain_jwts
        .split_first()
        .ok_or_else(|| FederationError::Validation("cached chain is empty".into()))?;
    if rest.is_empty() || rest.len() % 2 != 0 {
        return Err(FederationError::Validation(
            "cached chain must contain subordinate/superior JWS pairs".into(),
        ));
    }

    let leaf = verify_entity_configuration(leaf_jws)?;
    let mut chain = Vec::with_capacity(chain_jwts.len());
    chain.push(leaf);

    for pair in rest.chunks_exact(2) {
        let sub_stmt_jws = pair[0];
        let superior_config = verify_entity_configuration(pair[1])?;
        let sub_stmt = if superior_config.iss == anchor.entity_id {
            verify_entity_statement(sub_stmt_jws, &anchor.jwks)?
        } else {
            let superior_jwks = superior_config.parse_jwks()?;
            verify_entity_statement(sub_stmt_jws, &superior_jwks)?
        };
        chain.push(sub_stmt);
        chain.push(superior_config);
    }

    Ok(TrustChain {
        chain,
        anchor: anchor.clone(),
    })
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

pub(super) fn validate_resolved_chain_jws_alignment(
    resolved: &ResolvedTrustChain,
) -> Result<(), FederationError> {
    if resolved.chain_jwts.len() == resolved.trust_chain.chain.len() {
        Ok(())
    } else {
        Err(FederationError::Internal(
            "resolved trust-chain JWS artifact count does not match semantic chain".into(),
        ))
    }
}

pub(super) fn validate_cached_trust_chain(
    chain: TrustChain,
    cached: &StoredTrustChain,
    now: i64,
) -> Result<TrustChain, FederationError> {
    if cached.anchor_entity_id != chain.anchor.entity_id {
        return Err(FederationError::Validation(
            "cached chain anchor does not match cache key".into(),
        ));
    }

    let (leaf, rest) = chain
        .chain
        .split_first()
        .ok_or_else(|| FederationError::Validation("cached chain is empty".into()))?;
    if rest.is_empty() || rest.len() % 2 != 0 {
        return Err(FederationError::Validation(
            "cached chain must contain subordinate/superior pairs".into(),
        ));
    }
    if cached.leaf_entity_id != leaf.iss || cached.leaf_entity_id != leaf.sub {
        return Err(FederationError::Validation(
            "cached chain leaf does not match cache key".into(),
        ));
    }
    validate_entity_statement(leaf, now)?;
    validate_entity_configuration_link(leaf, &cached.leaf_entity_id)?;
    let leaf_entity_types = leaf_entity_types(leaf);

    let mut current_entity_id = leaf.iss.as_str();
    let mut last_subordinate: Option<&EntityStatement> = None;
    for (depth, pair) in rest.chunks_exact(2).enumerate() {
        let sub_stmt = &pair[0];
        let superior_config = &pair[1];

        validate_entity_statement(sub_stmt, now)?;
        validate_entity_statement(superior_config, now)?;
        validate_subordinate_statement_link(sub_stmt, superior_config, current_entity_id)?;
        validate_path_constraints(sub_stmt, &leaf_entity_types, depth)?;

        current_entity_id = superior_config.iss.as_str();
        last_subordinate = Some(sub_stmt);
    }

    if current_entity_id != chain.anchor.entity_id {
        return Err(FederationError::Validation(
            "cached chain does not terminate at configured trust anchor".into(),
        ));
    }
    let Some(anchor_subordinate) = last_subordinate else {
        return Err(FederationError::Validation(
            "cached chain missing trust-anchor subordinate statement".into(),
        ));
    };
    validate_anchor_subordinate_metadata_policy(&chain.anchor, anchor_subordinate)?;

    Ok(chain)
}
