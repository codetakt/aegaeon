use aegaeon_jose::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use super::metadata_policy::{apply_resolved, resolve_policies};
use super::FederationError;

/// OpenID Federation Entity Statement claims.
///
/// An Entity Statement is a signed JWT containing metadata about an entity in the federation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityStatement {
    /// Issuer: the entity that signed this statement.
    pub iss: String,
    /// Subject: the entity this statement describes.
    pub sub: String,
    /// Issued-at timestamp.
    pub iat: i64,
    /// Expiration timestamp.
    pub exp: i64,
    /// The subject's JSON Web Key Set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,
    /// Metadata indexed by entity type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, Value>>,
    /// Metadata policy constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_policy: Option<HashMap<String, Value>>,
    /// Trust chain constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    /// Trust marks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_marks: Option<Vec<TrustMark>>,
    /// Superior entity identifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_hints: Option<Vec<String>>,
    /// Optional issuing fetch endpoint URL carried by a Subordinate Statement JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_endpoint: Option<String>,
}

impl EntityStatement {
    /// Returns true if this is a self-signed Entity Configuration.
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.iss == self.sub
    }

    /// Parse the `jwks` field into a [`JwkSet`].
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when `jwks` is absent or invalid.
    pub fn parse_jwks(&self) -> Result<JwkSet, FederationError> {
        let jwks_value = self
            .jwks
            .as_ref()
            .ok_or(FederationError::MissingField("jwks"))?;
        super::keys::parse_federation_jwks(jwks_value.clone())
    }
}

/// Trust chain constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    /// Maximum path length from this entity to the leaf.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_path_length: Option<u32>,
    /// Allowed leaf entity types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_leaf_entity_types: Option<Vec<String>>,
}

/// Trust mark reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustMark {
    /// Trust mark identifier.
    #[serde(rename = "trust_mark_type", alias = "id")]
    pub id: String,
    /// The trust mark JWT.
    pub trust_mark: String,
}

/// Trust mark JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustMarkClaims {
    /// Trust mark issuer.
    pub iss: String,
    /// Subject entity.
    pub sub: String,
    /// Trust mark identifier.
    #[serde(rename = "trust_mark_type", alias = "id")]
    pub id: String,
    /// Issued-at timestamp.
    pub iat: i64,
    /// Expiration timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Reference to an entity statement about the Trust Mark Issuer.
    #[serde(
        rename = "ref",
        alias = "ref_",
        skip_serializing_if = "Option::is_none"
    )]
    pub ref_: Option<String>,
}

/// A configured trust anchor with pre-loaded JWKS.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// The trust anchor's entity identifier.
    pub entity_id: String,
    /// The trust anchor's public keys.
    pub jwks: JwkSet,
    /// Optional metadata policy that subordinate statements must match.
    pub metadata_policy: Option<Value>,
}

/// A verified trust chain from a leaf entity to a trust anchor.
#[derive(Debug, Clone)]
pub struct TrustChain {
    /// Ordered entity statements from leaf to trust anchor.
    pub chain: Vec<EntityStatement>,
    /// The configured trust anchor.
    pub anchor: TrustAnchor,
}

/// A verified trust chain plus the compact JWS artifacts used to verify it.
#[derive(Debug, Clone)]
pub struct ResolvedTrustChain {
    /// The semantic trust chain used by callers.
    pub trust_chain: TrustChain,
    /// Ordered compact JWS values matching `trust_chain.chain`.
    pub chain_jwts: Vec<String>,
}

impl ResolvedTrustChain {
    #[must_use]
    pub fn new(trust_chain: TrustChain, chain_jwts: Vec<String>) -> Self {
        Self {
            trust_chain,
            chain_jwts,
        }
    }

    #[must_use]
    pub fn into_trust_chain(self) -> TrustChain {
        self.trust_chain
    }
}

impl TrustChain {
    /// The leaf entity's self-signed Entity Configuration.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the chain is empty.
    pub fn leaf(&self) -> Result<&EntityStatement, FederationError> {
        self.chain.first().ok_or_else(|| {
            FederationError::Validation("trust chain is empty: missing leaf entity".into())
        })
    }

    /// The trust anchor's Entity Configuration.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the chain is empty.
    pub fn trust_anchor_config(&self) -> Result<&EntityStatement, FederationError> {
        self.chain.last().ok_or_else(|| {
            FederationError::Validation("trust chain is empty: missing trust anchor".into())
        })
    }

    /// Chain depth, measured as hops from leaf to anchor.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the chain is empty.
    pub fn depth(&self) -> Result<usize, FederationError> {
        self.chain
            .len()
            .checked_sub(1)
            .map(|edge_count| edge_count / 2)
            .ok_or_else(|| FederationError::Validation("trust chain is empty".into()))
    }

    /// Resolve policies, overlay immediate-superior metadata, then apply once.
    ///
    /// Requires a cryptographically verified canonical alternating C/S/C path.
    /// Typed construction alone does not authenticate statements. This method
    /// checks layout and identities, but does not verify signatures or expiry.
    /// The result is derived metadata and carries no signature of its own.
    ///
    /// # Errors
    /// Returns an error for malformed layout, policy or resulting metadata.
    pub fn resolved_metadata(&self) -> Result<Option<HashMap<String, Value>>, FederationError> {
        self.validate_metadata_layout()?;
        let policies = self
            .chain
            .iter()
            .skip(1)
            .step_by(2)
            .rev()
            .filter_map(|statement| statement.metadata_policy.as_ref());
        let policies = resolve_policies(policies)?;
        let Some(mut resolved) = self.leaf()?.metadata.clone() else {
            return Ok(None);
        };
        if let Some(overlay) = &self.chain[1].metadata {
            for (entity_type, metadata) in &mut resolved {
                let target = metadata.as_object_mut().ok_or_else(|| {
                    FederationError::MetadataPolicy("metadata must be an object".into())
                })?;
                if target.values().any(Value::is_null) {
                    return Err(FederationError::MetadataPolicy(
                        "null metadata parameter".into(),
                    ));
                }
                if let Some(superior) = overlay.get(entity_type) {
                    let superior = superior.as_object().ok_or_else(|| {
                        FederationError::MetadataPolicy(
                            "superior metadata must be an object".into(),
                        )
                    })?;
                    target.extend(superior.clone());
                }
            }
        }
        for (entity_type, metadata) in &mut resolved {
            *metadata = apply_resolved(
                metadata,
                policies.get(entity_type).unwrap_or(&Default::default()),
                Some(entity_type),
            )?;
        }
        Ok(Some(resolved))
    }

    fn validate_metadata_layout(&self) -> Result<(), FederationError> {
        self.leaf()?;
        let invalid = || {
            FederationError::Validation(
                "metadata resolution requires a canonical C/S/C chain".into(),
            )
        };
        if self.chain.len() < 3 || self.chain.len().is_multiple_of(2) {
            return Err(invalid());
        }
        if !self.leaf()?.is_self_signed()
            || self.trust_anchor_config()?.iss != self.anchor.entity_id
        {
            return Err(invalid());
        }
        for edge in self.chain.windows(3).step_by(2) {
            if !edge[2].is_self_signed()
                || edge[1].is_self_signed()
                || edge[1].sub != edge[0].sub
                || edge[1].iss != edge[2].iss
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
