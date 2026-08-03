// OpenID Connect Federation 1.0 — Entity Statement types, parsing, and
// trust chain resolution.
//
// Implements the client-side of OpenID Federation:
// - Entity Statement / Entity Configuration types (§3)
// - Subordinate Statement verification (§3.1)
// - Trust chain resolution from leaf to trust anchor (§4)
// - Metadata policy resolution with basic operators (§5)
// - .well-known/openid-federation endpoint URL construction (§6)
//
// Security properties verified by Tamarin model (proofs/tamarin/federation/trust_chain.spthy):
// - chain_to_trust_anchor: trusted entity must chain to an established TA
// - intermediate_chain_key_authenticity: all chain signatures verified
// - subordinate_statement_authenticity: issuer key must exist
// - metadata_policy_enforcement: metadata constrained by ancestor policies
// - entity_key_uniqueness: distinct entities have distinct keys
// - key_rotation_authorization: rotation requires old key or parent endorsement
//
// DB schema (Phase 2 — IMPLEMENTED):
//   See the federation tables in db/schema.sql
//   Tables: federation_trust_anchors, federation_entity_cache, federation_trust_chains
//   Repository traits: below; in-memory implementations are test-only.
//   PostgreSQL implementations: PgTrustAnchorRepository, PgEntityCacheRepository, PgTrustChainCacheRepository

#[cfg(test)]
use aegaeon_jose::jwk::Jwk;
use aegaeon_jose::jwk::JwkSet;
#[cfg(test)]
use aegaeon_jose::jws::VerificationKey;
use aegaeon_jose::jws::{self, Jws, JwsError};
use aegaeon_jose::policy::JoseContext;
#[cfg(test)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use std::collections::HashMap;
use thiserror::Error;

mod fetcher;
mod keys;
mod metadata_policy;
mod raw_payload;
mod repositories;
mod trust_chain;
mod trust_marks;
mod types;

pub use fetcher::{
    entity_configuration_url, normalize_federation_outbound_allowed_domains,
    subordinate_statement_url, validate_entity_url, FederationFetchFuture, FederationFetcher,
    FetchedEntityConfiguration, FetchedSubordinateStatement, HttpFederationFetcher,
};
pub use keys::{decode_jwk_material, verification_key_for_alg, DecodedKeyMaterial};
pub use metadata_policy::apply_metadata_policy;
pub use repositories::{
    resolve_trust_chain_cached, resolve_trust_chain_cached_with,
    resolve_trust_chain_jwts_cached_with, spawn_cache_cleanup, valid_federation_cache_max_entries,
    valid_federation_cache_ttl_secs, CachedFederationFetcher, EntityCacheRepository,
    FederationCacheConfig, PgEntityCacheRepository, PgTrustAnchorRepository,
    PgTrustChainCacheRepository, StoredEntityCache, StoredTrustAnchor, StoredTrustChain,
    TrustAnchorRepository, TrustChainCacheRepository, DEFAULT_FEDERATION_CACHE_MAX_ENTRIES,
    DEFAULT_FEDERATION_ENTITY_CACHE_TTL_SECS, DEFAULT_FEDERATION_TRUST_CHAIN_CACHE_TTL_SECS,
    MAX_FEDERATION_CACHE_MAX_ENTRIES, MAX_FEDERATION_CACHE_TTL_SECS,
};
#[cfg(test)]
pub(crate) use repositories::{
    InMemoryEntityCacheRepo, InMemoryTrustAnchorRepo, InMemoryTrustChainCacheRepo,
};
pub use trust_chain::{resolve_trust_chain, resolve_trust_chain_with_jwts};
#[cfg(test)]
use trust_marks::validate_trust_mark_claims;
pub use trust_marks::verify_trust_mark;
pub use types::{
    Constraints, EntityStatement, ResolvedTrustChain, TrustAnchor, TrustChain, TrustMark,
    TrustMarkClaims,
};

/// Maximum trust chain depth to prevent infinite loops.
const MAX_CHAIN_DEPTH: usize = 10;

/// Default clock skew leeway for temporal validation (seconds).
const DEFAULT_CLOCK_SKEW_SECS: i64 = 60;

// ─── Error Types ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FederationError {
    #[error("JWS error: {0}")]
    Jws(#[from] JwsError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JWK error: {0}")]
    Jwk(#[from] aegaeon_jose::jwk::JwkError),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("entity statement missing required field: {0}")]
    MissingField(&'static str),

    #[error("entity statement validation failed: {0}")]
    Validation(String),

    #[error("internal federation error: {0}")]
    Internal(String),

    #[error("self-signed entity configuration requires iss == sub")]
    IssSubMismatch,

    #[error("entity statement has expired")]
    Expired,

    #[error("entity statement not yet valid")]
    NotYetValid,

    #[error("no suitable signing key found in JWKS")]
    NoSuitableKey,

    #[error("trust chain resolution failed: {0}")]
    ChainResolution(String),

    #[error("trust chain exceeds maximum depth ({MAX_CHAIN_DEPTH})")]
    ChainTooDeep,

    #[error("metadata policy error: {0}")]
    MetadataPolicy(String),

    #[error("fetch error: {0}")]
    Fetch(String),

    #[error("unsupported key algorithm for federation JWS: {0}")]
    UnsupportedAlgorithm(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("trust mark verification failed: {0}")]
    TrustMark(String),

    #[error("max_path_length constraint violated: depth {depth} exceeds limit {max}")]
    MaxPathLengthExceeded { depth: u32, max: u32 },
}

// ─── Entity Statement Parsing ────────────────────────────────────────────

/// Parse an Entity Statement JWS without signature verification.
///
/// **Warning**: The returned [`EntityStatement`] has NOT been signature-verified.
/// Use [`verify_entity_statement`] for full verification.
///
/// # Errors
///
/// Returns [`FederationError`] when the compact JWS or decoded payload cannot be parsed.
pub fn parse_entity_statement_unverified(
    jws_compact: &str,
) -> Result<EntityStatement, FederationError> {
    let parsed = Jws::from_compact(jws_compact)?;
    let stmt = raw_payload::parse_entity_statement_payload(&parsed.payload)?;
    Ok(stmt)
}

/// Verify and parse an Entity Statement JWS against a known JWKS.
///
/// Used for subordinate statements (verify against the issuer's known JWKS).
///
/// Enforces Tamarin property `subordinate_statement_authenticity`:
/// the JWS signature must be verifiable with a key from the provided JWKS.
///
/// # Errors
///
/// Returns [`FederationError`] when no suitable key is available, signature verification fails, or
/// the payload cannot be parsed as an entity statement.
pub fn verify_entity_statement(
    jws_compact: &str,
    issuer_jwks: &JwkSet,
) -> Result<EntityStatement, FederationError> {
    let parsed = Jws::from_compact(jws_compact)?;
    let alg = &parsed.header.alg;
    let ctx = JoseContext::default();

    let mut last_err = None;
    for key in issuer_jwks.signature_keys() {
        // If JWS header specifies kid, only try matching keys
        if let Some(ref header_kid) = parsed.header.kid {
            if key.kid.as_deref() != Some(header_kid.as_str()) {
                continue;
            }
        }

        let decoded = match decode_jwk_material(key) {
            Ok(d) => d,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };

        let vk = match verification_key_for_alg(key, &decoded, alg) {
            Ok(vk) => vk,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };

        match jws::verify_compact_with_context(jws_compact, vk, &ctx) {
            Ok(payload_bytes) => {
                let stmt = raw_payload::parse_entity_statement_payload(&payload_bytes)?;
                return Ok(stmt);
            }
            Err(e) => {
                last_err = Some(FederationError::Jws(e));
            }
        }
    }

    Err(last_err.unwrap_or(FederationError::NoSuitableKey))
}

/// Verify a self-signed Entity Configuration.
///
/// The entity's JWKS is embedded in the payload. We:
/// 1. Parse the unverified payload to extract the JWKS
/// 2. Verify `iss == sub` (self-signed requirement)
/// 3. Verify the JWS signature against the embedded JWKS
///
/// # Errors
///
/// Returns [`FederationError`] when the entity configuration is not self-signed, the embedded JWKS
/// is missing or invalid, or the JWS cannot be verified.
pub fn verify_entity_configuration(jws_compact: &str) -> Result<EntityStatement, FederationError> {
    // Step 1: Parse unverified to get JWKS
    let unverified = parse_entity_statement_unverified(jws_compact)?;

    // Step 2: Require self-signed
    if !unverified.is_self_signed() {
        return Err(FederationError::IssSubMismatch);
    }

    // Step 3: Verify JWS against embedded JWKS
    let jwks = unverified.parse_jwks()?;
    verify_entity_statement(jws_compact, &jwks)
}

// ─── Temporal Validation ─────────────────────────────────────────────────

/// Validate temporal claims of an Entity Statement.
///
/// Note: Tamarin documents that temporal validation is NOT modeled symbolically
/// (Tamarin lacks monotonic time), so this function is the authoritative check.
///
/// # Errors
///
/// Returns [`FederationError`] when `iat`/`exp` are inconsistent, the statement has expired, or it
/// is not yet valid under the provided leeway window.
pub fn validate_temporal(
    stmt: &EntityStatement,
    now: i64,
    leeway_secs: i64,
) -> Result<(), FederationError> {
    if leeway_secs < 0 {
        return Err(FederationError::Validation(
            "leeway must be non-negative".into(),
        ));
    }
    if stmt.exp <= stmt.iat {
        return Err(FederationError::Validation(
            "exp must be greater than iat".into(),
        ));
    }
    let exp_with_leeway = stmt.exp.checked_add(leeway_secs).ok_or_else(|| {
        FederationError::Validation("exp plus leeway is outside representable time".into())
    })?;
    if now > exp_with_leeway {
        return Err(FederationError::Expired);
    }
    let now_with_leeway = now.checked_add(leeway_secs).ok_or_else(|| {
        FederationError::Validation("now plus leeway is outside representable time".into())
    })?;
    if now_with_leeway < stmt.iat {
        return Err(FederationError::NotYetValid);
    }
    Ok(())
}

/// Full validation of an Entity Statement (required fields + temporal).
///
/// # Errors
///
/// Returns [`FederationError`] when required claims are missing or temporal validation fails.
pub fn validate_entity_statement(stmt: &EntityStatement, now: i64) -> Result<(), FederationError> {
    if stmt.iss.is_empty() {
        return Err(FederationError::MissingField("iss"));
    }
    if stmt.sub.is_empty() {
        return Err(FederationError::MissingField("sub"));
    }
    // Self-signed entity configurations must include JWKS
    if stmt.is_self_signed() && stmt.jwks.is_none() {
        return Err(FederationError::MissingField("jwks"));
    }
    validate_temporal(stmt, now, DEFAULT_CLOCK_SKEW_SECS)
}

#[cfg(test)]
mod tests;
