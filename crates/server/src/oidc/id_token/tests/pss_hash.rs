use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256, Sha384, Sha512};

fn vectors(input: &str) -> [(&'static str, &'static str, String); 3] {
    [
        (
            "PS256",
            "RS256",
            URL_SAFE_NO_PAD.encode(&Sha256::digest(input)[..16]),
        ),
        (
            "PS384",
            "RS384",
            URL_SAFE_NO_PAD.encode(&Sha384::digest(input)[..24]),
        ),
        (
            "PS512",
            "RS512",
            URL_SAFE_NO_PAD.encode(&Sha512::digest(input)[..32]),
        ),
    ]
}

#[test]
fn oidc_pss_hash_adapter_preserves_source_bytes_and_rejects_name_aliases() -> TestResult {
    for input in [
        "sample-access-token",
        "authorization-code-123",
        "",
        " leading\0trailing ",
        "é",
    ] {
        for (alg, _, expected) in vectors(input) {
            assert_eq!(compute_hash(input, alg)?, expected);
        }
    }
    for alg in ["ps256", "PS256 ", "PS256\0", "PS256-extra", "PS257", "none"] {
        assert!(compute_hash("source", alg).is_err(), "{alg:?}");
    }
    Ok(())
}

#[cfg(not(feature = "verified-claim"))]
#[test]
fn oidc_pss_hash_fallback_uses_independent_sha2_vectors() -> TestResult {
    for (alg, _, expected) in vectors("sample-access-token") {
        for failure in [
            OidcHashError::Unavailable,
            OidcHashError::ComputationFailed,
            OidcHashError::NullDigest,
        ] {
            assert_eq!(
                finalize_hash_result(Err(failure), "sample-access-token", alg)?,
                expected
            );
        }
    }
    Ok(())
}

#[cfg(feature = "verified-claim")]
#[test]
fn oidc_pss_hash_verified_profile_preserves_fail_closed_errors() {
    for (alg, _, _) in vectors("sample-access-token") {
        for failure in [
            OidcHashError::Unavailable,
            OidcHashError::ComputationFailed,
            OidcHashError::NullDigest,
        ] {
            assert!(matches!(
                finalize_hash_result(Err(failure), "sample-access-token", alg),
                Err(Error::ServerError(_))
            ));
        }
    }
}

#[test]
fn oidc_pss_hash_errors_preserve_bounds_and_invalid_algorithm_rejection() {
    for alg in ["PS256", "PS384", "PS512"] {
        for failure in [
            OidcHashError::InputTooLarge,
            OidcHashError::InvalidAlgorithm,
        ] {
            assert!(matches!(
                finalize_hash_result(Err(failure), "source", alg),
                Err(Error::InvalidRequest(_))
            ));
        }
    }
}

#[test]
#[ignore = "requires the actual ffi/lowstar_hash runtime; run explicitly in that feature lane"]
fn oidc_pss_hash_runtime_mapping_keeps_ffi_algorithm_contract() -> TestResult {
    for input in ["sample-access-token", "authorization-code-123"] {
        for (pss, digest_selector, expected) in vectors(input) {
            let native = ffi::id_token::compute_oidc_hash_bytes(digest_selector, input.as_bytes())
                .map_err(|e| format!("required native runtime unavailable or failed: {e:?}"))?;
            assert_eq!(URL_SAFE_NO_PAD.encode(native), expected);
            assert_eq!(compute_hash(input, pss)?, expected);
            assert_eq!(
                ffi::id_token::compute_oidc_hash_bytes(pss, input.as_bytes()),
                Err(OidcHashError::InvalidAlgorithm)
            );
        }
    }
    Ok(())
}
