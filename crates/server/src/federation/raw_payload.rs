mod structural;

use super::{EntityStatement, FederationError, TrustMarkClaims};
use aegaeon_jose::raw_json::{self, RawJsonBackend, RawJsonSurface};

pub(super) fn parse_entity_statement_payload(
    payload: &[u8],
) -> Result<EntityStatement, FederationError> {
    let policy = raw_json::backend_policy_for_surface(RawJsonSurface::FederationEntityStatement)
        .map_err(|_| {
            FederationError::Internal(
                "unsupported raw JSON backend for federation-entity-statement".into(),
            )
        })?;
    match policy.backend {
        RawJsonBackend::SerdeCompat => Err(FederationError::Internal(
            "serde-compat backend is not available for federation-entity-statement".into(),
        )),
        RawJsonBackend::VerifiedStructuralV1 => {
            structural::parse_entity_statement_payload_verified_structural(payload)
        }
    }
}

pub(super) fn parse_trust_mark_claims_payload(
    payload: &[u8],
) -> Result<TrustMarkClaims, FederationError> {
    let policy = raw_json::backend_policy_for_surface(RawJsonSurface::FederationTrustMark)
        .map_err(|_| {
            FederationError::Internal(
                "unsupported raw JSON backend for federation-trust-mark".into(),
            )
        })?;
    match policy.backend {
        RawJsonBackend::SerdeCompat => Err(FederationError::Internal(
            "serde-compat backend is not available for federation-trust-mark".into(),
        )),
        RawJsonBackend::VerifiedStructuralV1 => {
            structural::parse_trust_mark_claims_payload_verified_structural(payload)
        }
    }
}
