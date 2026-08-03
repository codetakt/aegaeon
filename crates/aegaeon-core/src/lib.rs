#![forbid(unsafe_code)]
//! Helpers for embedding and validating the Verified Core WASM artefact.
//!
//! This crate is intentionally lightweight: it bundles the generated
//! `verified_core.wasm` and `manifest.json` produced by
//! `scripts/extraction/package_verified_core.sh`, exposing convenience
//! accessors and basic integrity checks. It is not the final runtime adapter;
//! rather, it provides a smoke-test harness and artefact access that other
//! layers (TypeScript/Rust SDKs) can build upon.

use aegaeon_crypto::hash::sha256_hex as compute_sha256_hex;
use std::time::SystemTime;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_verified_core.rs"));
}

/// Parsed manifest for the Verified Core artefact.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Manifest {
    pub artifact: String,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    pub sha256: String,
    #[serde(default)]
    pub sri: Option<String>,
    #[serde(default)]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub source_commit: Option<String>,
}

/// Return the embedded manifest.
///
/// # Errors
///
/// Returns the `serde_json` parse error when the embedded manifest JSON is malformed.
pub fn manifest() -> Result<Manifest, serde_json::Error> {
    serde_json::from_str(embedded::EMBEDDED_MANIFEST_JSON)
}

/// Return the embedded WASM bytes.
#[must_use]
pub fn wasm_bytes() -> &'static [u8] {
    embedded::EMBEDDED_WASM_BYTES
}

/// Compute the lowercase hex SHA-256 digest of the embedded WASM.
#[must_use]
pub fn wasm_sha256() -> String {
    compute_sha256_hex(wasm_bytes())
}

/// Perform a lightweight integrity check (hash + optional size).
///
/// # Errors
///
/// Returns an error when the embedded manifest cannot be parsed, when the manifest hash does not
/// match the embedded WASM, or when the optional manifest size does not match the embedded WASM
/// size.
pub fn verify_integrity() -> Result<(), String> {
    let manifest = manifest().map_err(|error| format!("manifest parse failed: {error}"))?;
    let actual_hash = wasm_sha256();
    if manifest.sha256 != actual_hash {
        return Err(format!(
            "sha256 mismatch: manifest={}, actual={actual_hash}",
            manifest.sha256
        ));
    }

    if let Some(expected_size) = manifest.size_bytes {
        if expected_size != wasm_bytes().len() as u64 {
            return Err(format!(
                "size mismatch: manifest={} wasm={}",
                expected_size,
                wasm_bytes().len()
            ));
        }
    }

    Ok(())
}

/// Convenience accessor mirroring the manifest timestamp.
///
/// # Errors
///
/// Returns the `serde_json` parse error when the embedded manifest JSON is malformed.
pub fn generated_timestamp() -> Result<Option<SystemTime>, serde_json::Error> {
    manifest().map(|manifest| {
        manifest
            .generated_at
            .as_deref()
            .and_then(|s| humantime::parse_rfc3339(s).ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_matches_embedded_wasm() {
        assert!(matches!(verify_integrity(), Ok(())));
    }
}
