use std::time::Duration;

use crate::federation::{EntityStatement, FederationError};

fn federation_cache_ttl_secs_i64(
    ttl: Duration,
    label: &'static str,
) -> Result<i64, FederationError> {
    i64::try_from(ttl.as_secs())
        .map_err(|_| FederationError::Validation(format!("{label} cache TTL is too large")))
}

pub(in crate::federation) fn trust_chain_cache_expires_at(
    now: i64,
    configured_ttl: Duration,
    chain: &[EntityStatement],
) -> Result<i64, FederationError> {
    let ttl_secs = federation_cache_ttl_secs_i64(configured_ttl, "federation trust-chain")?;
    let configured_expires_at = now.checked_add(ttl_secs).ok_or_else(|| {
        FederationError::Validation("federation trust-chain cache expiry overflow".into())
    })?;
    Ok(chain
        .iter()
        .map(|stmt| stmt.exp)
        .min()
        .map_or(configured_expires_at, |statement_exp| {
            configured_expires_at.min(statement_exp)
        }))
}

pub(super) fn entity_cache_expires_at(
    now: i64,
    configured_ttl: Duration,
    statement: &EntityStatement,
) -> Result<i64, FederationError> {
    let ttl_secs = federation_cache_ttl_secs_i64(configured_ttl, "federation entity")?;
    let configured_expires_at = now.checked_add(ttl_secs).ok_or_else(|| {
        FederationError::Validation("federation entity cache expiry overflow".into())
    })?;
    Ok(configured_expires_at.min(statement.exp))
}
