#![cfg(feature = "lowstar_hash")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ffi::id_token::{compute_oidc_hash_bytes, OidcHashError};
use sha2::{Digest, Sha256, Sha384, Sha512};

fn expected_oidc_hash_bytes(alg: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    match alg {
        "RS256" | "ES256" | "HS256" => Ok(Sha256::digest(input)[..16].to_vec()),
        "RS384" | "ES384" | "HS384" => Ok(Sha384::digest(input)[..24].to_vec()),
        "RS512" | "ES512" | "HS512" => Ok(Sha512::digest(input)[..32].to_vec()),
        _ => Err(format!("unsupported algorithm in test fixture: {alg}")),
    }
}

#[test]
fn oidc_hash_runtime_rs256_vector() {
    let digest_result = compute_oidc_hash_bytes("RS256", b"sample-access-token");
    assert!(digest_result.is_ok(), "RS256 runtime hash should succeed");
    let Ok(digest) = digest_result else {
        return;
    };

    assert_eq!(URL_SAFE_NO_PAD.encode(digest), "EN9PvSfRnJ9qwbHAFRGqMw");
}

#[test]
fn oidc_hash_runtime_rs512_vector() {
    let digest_result = compute_oidc_hash_bytes("RS512", b"sample-access-token");
    assert!(digest_result.is_ok(), "RS512 runtime hash should succeed");
    let Ok(digest) = digest_result else {
        return;
    };

    assert_eq!(
        URL_SAFE_NO_PAD.encode(digest),
        "kaV9BW4X8QKnv2uo3eN9Uh27bcmgOg2GoEPwQX9QGYI"
    );
}

#[test]
fn oidc_hash_runtime_rejects_unknown_algorithm() {
    let err_result = compute_oidc_hash_bytes("none", b"sample-access-token");
    assert!(err_result.is_err(), "unknown algorithm should fail");
    let Err(err) = err_result else {
        return;
    };

    assert_eq!(err, OidcHashError::InvalidAlgorithm);
}

#[test]
fn oidc_hash_runtime_rejects_ps_algorithms() {
    for alg in ["PS256", "PS384", "PS512"] {
        let err_result = compute_oidc_hash_bytes(alg, b"sample-access-token");
        assert!(err_result.is_err(), "{alg} should fail");
        let Err(err) = err_result else {
            return;
        };

        assert_eq!(err, OidcHashError::InvalidAlgorithm);
    }
}

#[test]
fn oidc_hash_runtime_matches_rust_digest_for_supported_algorithms() -> Result<(), String> {
    let cases = [
        ("RS256", b"sample-access-token".as_slice()),
        ("ES256", b"sample-access-token".as_slice()),
        ("HS256", b"sample-access-token".as_slice()),
        ("RS384", b"authorization-code-123".as_slice()),
        ("ES384", b"authorization-code-123".as_slice()),
        ("HS384", b"authorization-code-123".as_slice()),
        ("RS512", b"refresh-token-xyz".as_slice()),
        ("ES512", b"refresh-token-xyz".as_slice()),
        ("HS512", b"refresh-token-xyz".as_slice()),
        ("RS256", b"".as_slice()),
        ("RS384", b"".as_slice()),
        ("RS512", b"".as_slice()),
    ];

    for (alg, input) in cases {
        let digest = compute_oidc_hash_bytes(alg, input)
            .map_err(|err| format!("{alg} runtime hash should succeed: {err:?}"))?;
        assert_eq!(
            digest,
            expected_oidc_hash_bytes(alg, input)?,
            "{alg} runtime digest should match Rust SHA-2 truncation",
        );
    }
    Ok(())
}

#[test]
fn oidc_hash_runtime_uses_expected_truncation_lengths() -> Result<(), String> {
    let cases = [
        ("RS256", 16usize),
        ("ES256", 16usize),
        ("HS256", 16usize),
        ("RS384", 24usize),
        ("ES384", 24usize),
        ("HS384", 24usize),
        ("RS512", 32usize),
        ("ES512", 32usize),
        ("HS512", 32usize),
    ];

    for (alg, expected_len) in cases {
        let digest = compute_oidc_hash_bytes(alg, b"length-check")
            .map_err(|err| format!("{alg} runtime hash should succeed: {err:?}"))?;
        assert_eq!(
            digest.len(),
            expected_len,
            "{alg} truncation length mismatch"
        );
    }
    Ok(())
}

#[test]
fn oidc_hash_runtime_rejects_interior_nul_algorithm() {
    let err_result = compute_oidc_hash_bytes("RS256\0lowstar", b"sample-access-token");
    assert!(err_result.is_err(), "interior NUL algorithm should fail");
    let Err(err) = err_result else {
        return;
    };

    assert_eq!(err, OidcHashError::InvalidAlgorithm);
}
