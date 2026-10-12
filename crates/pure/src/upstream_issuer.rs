//! Frozen upstream issuer policy, shared by production and Kani.
//! URL admission, decoding and trusted metadata are caller responsibilities.

pub const POLICY_VERSION: u32 = 1;

pub const fn supported_policy_version(version: u32) -> bool {
    version == POLICY_VERSION
}

pub fn requires_issuer(profile_requires: bool, discovery_supports: Option<bool>) -> bool {
    profile_requires || discovery_supports == Some(true)
}

/// Compare decoded identifier bytes without URL canonicalization.
pub fn issuer_matches(expected: &[u8], received: &[u8]) -> bool {
    expected == received
}
