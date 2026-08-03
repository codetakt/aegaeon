use serde_json::Value;
use uuid::Uuid;

use crate::federation::{FederationError, JwkSet, TrustAnchor};

/// A trust anchor row as stored in the database.
#[derive(Debug, Clone)]
pub struct StoredTrustAnchor {
    pub id: Uuid,
    pub environment_id: Uuid,
    pub entity_id: String,
    pub jwks: Value,
    pub metadata_policy: Option<Value>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl StoredTrustAnchor {
    /// Convert to the in-memory [`TrustAnchor`] used by the resolution algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when the stored JWKS value cannot be parsed.
    pub fn to_trust_anchor(&self) -> Result<TrustAnchor, FederationError> {
        let jwks = JwkSet::from_value(self.jwks.clone())?;
        Ok(TrustAnchor {
            entity_id: self.entity_id.clone(),
            jwks,
            metadata_policy: self.metadata_policy.clone(),
        })
    }
}

/// A cached entity configuration row.
#[derive(Debug, Clone)]
pub struct StoredEntityCache {
    pub id: Uuid,
    pub environment_id: Uuid,
    pub entity_id: String,
    pub entity_configuration_jws: String,
    pub parsed_statement: Value,
    pub fetched_at: i64,
    pub expires_at: i64,
}

/// A cached trust chain row.
#[derive(Debug, Clone)]
pub struct StoredTrustChain {
    pub id: Uuid,
    pub environment_id: Uuid,
    pub leaf_entity_id: String,
    pub anchor_entity_id: String,
    pub chain_jwts: Value,
    pub resolved_at: i64,
    pub expires_at: i64,
}
