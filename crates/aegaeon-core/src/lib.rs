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
use std::borrow::Cow;
use std::time::{Duration, SystemTime};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

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
            .and_then(parse_generated_timestamp)
    })
}

// Keep the existing UTC-only, post-epoch accessor boundary. The packaging
// script emits this form; a malformed optional timestamp remains None.
fn parse_generated_timestamp(value: &str) -> Option<SystemTime> {
    if value.as_bytes().get(10) != Some(&b'T')
        || !(value.ends_with('Z') || value.ends_with("+00:00"))
    {
        return None;
    }
    // Preserve the former parser's leap-second normalization to second 59,
    // including its fractional part, instead of the RFC parser's final nanosecond.
    let normalized = if value.get(17..19) == Some("60") {
        let mut normalized = value.to_owned();
        normalized.replace_range(17..19, "59");
        Cow::Owned(normalized)
    } else {
        Cow::Borrowed(value)
    };
    let timestamp = OffsetDateTime::parse(&normalized, &Rfc3339).ok()?;
    let seconds = u64::try_from(timestamp.unix_timestamp()).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(seconds, timestamp.nanosecond()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_matches_embedded_wasm() {
        assert!(matches!(verify_integrity(), Ok(())));
    }

    #[test]
    fn generated_timestamp_preserves_utc_seconds_and_fractional_precision() {
        for (value, seconds, nanos) in [
            ("1970-01-01T00:00:00Z", 0, 0),
            ("1970-01-01T00:00:01+00:00", 1, 0),
            ("2024-02-29T12:34:56Z", 1_709_210_096, 0),
            ("1970-01-01T00:00:00.123456789Z", 0, 123_456_789),
            ("1970-01-01T00:00:00.1234567899+00:00", 0, 123_456_789),
            ("2016-12-31T23:59:60Z", 1_483_228_799, 0),
            ("2016-12-31T23:59:60.125Z", 1_483_228_799, 125_000_000),
        ] {
            assert_eq!(
                parse_generated_timestamp(value),
                SystemTime::UNIX_EPOCH.checked_add(Duration::new(seconds, nanos)),
                "{value}"
            );
        }
    }

    #[test]
    fn generated_timestamp_refuses_invalid_or_unsupported_values() {
        for value in [
            "",
            "garbage",
            "2024-02-30T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "1969-12-31T23:59:59Z",
            "2024-01-01 00:00:00Z",
            "2024-01-01t00:00:00z",
            "2024-01-01T00:00:00",
            "2024-01-01T00:00:00+01:00",
            "2024-01-01T00:00:00-00:00",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:60:60Z",
            "2024-01-01T00:00:61Z",
            "2024-01-01T00:00:00.Z",
            "2024-01-01T00:00:00ZjunkZ",
            "２０２４-01-01T00:00:00Z",
        ] {
            assert_eq!(parse_generated_timestamp(value), None, "{value}");
        }
        let missing: Manifest =
            serde_json::from_str(r#"{"artifact":"fixture","sha256":"fixture"}"#).unwrap();
        assert!(missing.generated_at.is_none());
        assert!(serde_json::from_str::<Manifest>(
            r#"{"artifact":"fixture","sha256":"fixture","generated_at":42}"#
        )
        .is_err());
    }
}
