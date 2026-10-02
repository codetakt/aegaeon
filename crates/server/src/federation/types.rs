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
    /// Critical additional metadata policy operators declared by a Subordinate Statement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_policy_crit: Option<Vec<String>>,
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
        Ok(JwkSet::from_value(jwks_value.clone())?)
    }
}

/// Trust chain constraints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Constraints {
    /// Maximum path length from this entity to the leaf.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_path_length: Option<u32>,
    /// Standard restrictions on all subordinate Entity Identifier hosts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub naming_constraints: Option<NamingConstraints>,
    /// Standard metadata type filter. `federation_entity` is always retained
    /// and must not occur in this list. An empty list excludes all other types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_entity_types: Option<Vec<String>>,
    /// Local any-match restriction on the original leaf-declared types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_leaf_entity_types: Option<Vec<String>>,
}

/// URI host namespaces permitted or excluded by a superior.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamingConstraints {
    /// Omission is unrestricted; a present empty list permits no names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permitted: Option<Vec<String>>,
    /// Any matching exclusion takes precedence over permission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded: Option<Vec<String>>,
}

impl Constraints {
    pub(in crate::federation) fn validate(&self) -> Result<(), FederationError> {
        if let Some(naming) = &self.naming_constraints {
            naming.validate()?;
        }
        if self.allowed_entity_types.as_ref().is_some_and(|types| {
            types
                .iter()
                .any(|entity_type| entity_type == "federation_entity")
        }) {
            return Err(FederationError::Validation(
                "allowed_entity_types must not include federation_entity".into(),
            ));
        }
        Ok(())
    }
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
    /// Optional local equality pin for the anchor-issued subordinate policy.
    /// None adds no local pin; signed policies still undergo full resolution.
    pub metadata_policy: Option<Value>,
}

/// A chain from a leaf entity to a configured trust anchor.
///
/// Successful resolver APIs verify signatures, path and metadata policies.
/// Constructing this public type directly does not attest those checks.
#[derive(Debug, Clone)]
pub struct TrustChain {
    /// Ordered entity statements from leaf to trust anchor.
    pub chain: Vec<EntityStatement>,
    /// The configured trust anchor.
    pub anchor: TrustAnchor,
}

/// A trust chain plus its compact JWS artifacts.
///
/// Successful resolver APIs validate the original signed path and metadata
/// policy before returning. Public construction alone attests no validation.
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

    /// Resolve policies, overlay superior metadata, filter entity types, then apply.
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
        super::naming_constraints::validate_chain_names(&self.chain)?;
        // Collect and validate every declaration before any policy is processed,
        // including declarations on types that will be absent or filtered out.
        let mut critical = std::collections::BTreeSet::new();
        for statement in &self.chain {
            if let Some(names) = &statement.metadata_policy_crit {
                if statement.is_self_signed() {
                    return Err(FederationError::Validation(
                        "metadata_policy_crit is subordinate-only".into(),
                    ));
                }
                super::metadata_policy::validate_critical_names(names)?;
                critical.extend(names.iter().map(String::as_str));
            }
        }
        let constraints: Vec<_> = self
            .chain
            .iter()
            .skip(1)
            .step_by(2)
            .filter_map(|statement| statement.constraints.as_ref())
            .collect();
        for constraint in &constraints {
            constraint.validate()?;
        }
        let policies = self
            .chain
            .iter()
            .skip(1)
            .step_by(2)
            .rev()
            .filter_map(|statement| statement.metadata_policy.as_ref());
        let policies = resolve_policies(policies, &critical)?;
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
        // Restrict the derived view only, after the immediate-S overlay and
        // before policy application. Every original policy was validated above.
        resolved.retain(|entity_type, _| {
            entity_type == "federation_entity"
                || constraints.iter().all(|constraint| {
                    constraint
                        .allowed_entity_types
                        .as_ref()
                        .is_none_or(|allowed| allowed.contains(entity_type))
                })
        });
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
