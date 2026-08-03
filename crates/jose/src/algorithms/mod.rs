// JOSE Algorithm implementations
// RFC 7518 compliant

pub mod rsa_pss;

pub use rsa_pss::*;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AlgorithmError {
    #[error("Unsupported algorithm: {0}")]
    Unsupported(String),

    #[error("Invalid key format: {0}")]
    InvalidKey(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Signing operation failed: {0}")]
    SigningFailed(String),
}

/// Supported JWA algorithms per RFC 7518
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    // HMAC
    HS256,
    HS384,
    HS512,

    // RSA
    RS256,
    RS384,
    RS512,

    // RSA-PSS
    PS256,
    PS384,
    PS512,

    // ECDSA
    ES256,
    ES384,
    ES512,

    // EdDSA
    EdDSA,
}

impl Algorithm {
    /// Parse a JOSE `alg` string into a supported [`Algorithm`].
    ///
    /// # Errors
    ///
    /// Returns [`AlgorithmError::Unsupported`] when `s` is not in the current
    /// algorithm table.
    pub fn from_string(s: &str) -> Result<Self, AlgorithmError> {
        match s {
            "HS256" => Ok(Algorithm::HS256),
            "HS384" => Ok(Algorithm::HS384),
            "HS512" => Ok(Algorithm::HS512),
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "RS512" => Ok(Algorithm::RS512),
            "PS256" => Ok(Algorithm::PS256),
            "PS384" => Ok(Algorithm::PS384),
            "PS512" => Ok(Algorithm::PS512),
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            "ES512" => Ok(Algorithm::ES512),
            "EdDSA" => Ok(Algorithm::EdDSA),
            _ => Err(AlgorithmError::Unsupported(s.to_string())),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::PS256 => "PS256",
            Algorithm::PS384 => "PS384",
            Algorithm::PS512 => "PS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::ES512 => "ES512",
            Algorithm::EdDSA => "EdDSA",
        }
    }

    /// Returns true if this algorithm is in the verified allowlist.
    ///
    /// Algorithms verified across both signing and verification operations.
    ///
    /// PS256 is intentionally excluded here because only verification is
    /// verified; [`CryptoProfile::allows`] admits it for verification dispatch.
    /// The algorithms represented here have HACL*/`EverCrypt` implementations:
    /// - HMAC: HS256, HS384, HS512 (Spec.Agile.HMAC)
    /// - `EdDSA`: Ed25519 only (Spec.Ed25519)
    ///
    /// See `fstar/jose/Jose.Alg_policy.fst:verified_allowed` and
    /// `docs/verification/claims/crypto-allowlist.md`.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(
            self,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 | Algorithm::EdDSA
        )
    }
}

/// Crypto profile controlling algorithm dispatch.
///
/// When `Verified`, only algorithms with HACL*/`EverCrypt` implementations
/// are accepted. When `Compat`, all supported algorithms are available
/// using native Rust libraries (ring, aws-lc-rs, sha2, hmac).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoProfile {
    /// Only verified algorithms (HS256/384/512, PS256, `EdDSA`). Rejects all others.
    Verified,
    /// All supported algorithms allowed. Native Rust implementations.
    Compat,
}

impl CryptoProfile {
    /// Parse from environment variable `AEGAEON_CRYPTO_PROFILE`.
    ///
    /// Accepted values (case-insensitive, trimmed): `"verified"`, `"compat"`.
    /// Unset or empty defaults to `Compat`.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("AEGAEON_CRYPTO_PROFILE") {
            Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
                "verified" => Self::Verified,
                _ => Self::Compat,
            },
            Err(_) => Self::Compat,
        }
    }

    /// Returns true if the given algorithm is allowed under this profile.
    ///
    /// This is the admission check for the verified JOSE dispatch
    /// ([`crate::jws::verify_compact_with_profile`]), where PS256 verification
    /// is routed to `Hacl_RSAPSS`. Call sites that dispatch non-promoted
    /// algorithms to a compat backend must use
    /// [`CryptoProfile::allows_on_compat_dispatch`] instead.
    #[must_use]
    pub fn allows(&self, alg: &Algorithm) -> bool {
        match self {
            CryptoProfile::Compat => true,
            CryptoProfile::Verified => alg.is_verified() || matches!(alg, Algorithm::PS256),
        }
    }

    /// Profile admission for call sites whose non-promoted verification
    /// dispatch uses a compat backend (e.g. `jsonwebtoken`) rather than the
    /// verified JOSE dispatch.
    ///
    /// PS256 is excluded here even though [`CryptoProfile::allows`] admits it:
    /// its verified promotion covers only the `Hacl_RSAPSS`-backed dispatch,
    /// so surfaces that verify through a compat backend must keep rejecting it
    /// under `Verified` until they are routed through the verified dispatch.
    #[must_use]
    pub fn allows_on_compat_dispatch(&self, alg: &Algorithm) -> bool {
        match self {
            CryptoProfile::Compat => true,
            CryptoProfile::Verified => alg.is_verified(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_verified_matches_allowlist() {
        assert!(Algorithm::HS256.is_verified());
        assert!(Algorithm::HS384.is_verified());
        assert!(Algorithm::HS512.is_verified());
        assert!(Algorithm::EdDSA.is_verified());

        assert!(!Algorithm::RS256.is_verified());
        assert!(!Algorithm::RS384.is_verified());
        assert!(!Algorithm::RS512.is_verified());
        assert!(!Algorithm::PS256.is_verified());
        assert!(!Algorithm::PS384.is_verified());
        assert!(!Algorithm::PS512.is_verified());
        assert!(!Algorithm::ES256.is_verified());
        assert!(!Algorithm::ES384.is_verified());
        assert!(!Algorithm::ES512.is_verified());
    }

    #[test]
    fn crypto_profile_compat_allows_all() {
        let profile = CryptoProfile::Compat;
        assert!(profile.allows(&Algorithm::HS256));
        assert!(profile.allows(&Algorithm::RS256));
        assert!(profile.allows(&Algorithm::PS256));
        assert!(profile.allows(&Algorithm::ES256));
        assert!(profile.allows(&Algorithm::EdDSA));
    }

    #[test]
    fn crypto_profile_verified_rejects_non_verified() {
        let profile = CryptoProfile::Verified;
        assert!(profile.allows(&Algorithm::HS256));
        assert!(profile.allows(&Algorithm::HS384));
        assert!(profile.allows(&Algorithm::HS512));
        assert!(profile.allows(&Algorithm::PS256));
        assert!(profile.allows(&Algorithm::EdDSA));

        assert!(!profile.allows(&Algorithm::RS256));
        assert!(!profile.allows(&Algorithm::PS384));
        assert!(!profile.allows(&Algorithm::ES256));
    }

    #[test]
    fn crypto_profile_compat_dispatch_excludes_ps256_when_verified() {
        let profile = CryptoProfile::Verified;
        assert!(profile.allows_on_compat_dispatch(&Algorithm::HS256));
        assert!(profile.allows_on_compat_dispatch(&Algorithm::EdDSA));
        assert!(!profile.allows_on_compat_dispatch(&Algorithm::PS256));
        assert!(!profile.allows_on_compat_dispatch(&Algorithm::RS256));

        let compat = CryptoProfile::Compat;
        assert!(compat.allows_on_compat_dispatch(&Algorithm::PS256));
        assert!(compat.allows_on_compat_dispatch(&Algorithm::ES256));
    }
}
