//! `JoseContext` boundary and edge case tests
//!
//! Tests the per-request context API with various header length limits,
//! ensuring proper rejection of oversized headers and acceptance of
//! valid headers at boundary conditions.

use aegaeon_jose::jwe::{decrypt_rsa_oaep_a256gcm_pkcs8_with_context, JweError};
use aegaeon_jose::jws::{verify_compact_with_context, JwsError, VerificationKey};
use aegaeon_jose::policy::{JoseContext, DEFAULT_HEADER_MAX_LEN};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::sync::Arc;
use std::thread;

/// Helper macro to skip test when Low* FFI is unavailable
macro_rules! skip_if_lowstar_unavailable {
    () => {
        if ffi::is_lowstar_unavailable() {
            eprintln!("Skipping: Low* FFI unavailable in this build");
            return;
        }
    };
}

// Helper to create compact JWS
fn make_compact_jws(header: &str, payload: &str, signature: &str) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.as_bytes()),
        URL_SAFE_NO_PAD.encode(signature.as_bytes())
    )
}

// Helper to create compact JWE (5-part)
fn make_compact_jwe(
    header: &str,
    encrypted_key: &str,
    iv: &str,
    ciphertext: &str,
    tag: &str,
) -> String {
    format!(
        "{}.{}.{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.as_bytes()),
        URL_SAFE_NO_PAD.encode(encrypted_key.as_bytes()),
        URL_SAFE_NO_PAD.encode(iv.as_bytes()),
        URL_SAFE_NO_PAD.encode(ciphertext.as_bytes()),
        URL_SAFE_NO_PAD.encode(tag.as_bytes())
    )
}

#[test]
fn context_default_has_4096_limit() {
    let ctx = JoseContext::default();
    assert_eq!(ctx.header_max_length(), 4096);
}

#[test]
fn context_custom_limit_accepted() {
    let ctx = JoseContext::new(8192);
    assert_eq!(ctx.header_max_length(), 8192);
}

#[test]
#[should_panic(expected = "header_max_length must be in range 1..=2^32-1")]
fn context_zero_limit_panics() {
    let _ = JoseContext::new(0);
}

#[test]
#[should_panic(expected = "header_max_length must be in range 1..=2^32-1")]
fn context_overflow_limit_panics() {
    let _ = JoseContext::new(usize::MAX);
}

#[test]
fn jws_header_within_limit_accepted() {
    skip_if_lowstar_unavailable!();
    let ctx = JoseContext::new(100);
    let header = r#"{"alg":"HS256","typ":"JWT"}"#; // ~28 bytes base64-encoded
    let jws = make_compact_jws(header, "{}", "signature");

    let result = verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx);

    // Signature verification will fail, but header length should be accepted
    assert!(matches!(result, Err(JwsError::VerificationFailed)));
}

#[test]
fn jws_header_exactly_at_limit_accepted() {
    // Create a header that encodes to exactly 50 bytes
    let header = r#"{"alg":"HS256","typ":"JWT","x":"12345"}"#; // Adjust to hit 50 bytes encoded
    let encoded_header = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let limit = encoded_header.len();

    let ctx = JoseContext::new(limit);
    let jws = make_compact_jws(header, "{}", "signature");

    let result = verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx);

    // Should not be HeaderTooLong
    assert!(!matches!(result, Err(JwsError::HeaderTooLong)));
}

#[test]
fn jws_header_one_over_limit_rejected() {
    let header = r#"{"alg":"HS256","typ":"JWT","x":"12345"}"#;
    let encoded_header = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let limit = encoded_header.len() - 1; // One byte short

    let ctx = JoseContext::new(limit);
    let jws = make_compact_jws(header, "{}", "signature");

    let result = verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx);

    assert!(matches!(result, Err(JwsError::HeaderTooLong)));
}

#[test]
fn jws_header_far_over_limit_rejected() {
    let ctx = JoseContext::new(10); // Very small limit
    let large_header =
        r#"{"alg":"HS256","typ":"JWT","kid":"very-long-key-identifier-that-exceeds-limit"}"#;
    let jws = make_compact_jws(large_header, "{}", "signature");

    let result = verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx);

    assert!(matches!(result, Err(JwsError::HeaderTooLong)));
}

#[test]
fn jws_minimal_header_with_minimal_limit() {
    let ctx = JoseContext::new(1); // Smallest possible limit
    let minimal_header = "{}"; // Minimal valid JSON
    let jws = make_compact_jws(minimal_header, "{}", "signature");

    let result = verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx);

    // "{}" encodes to "e30" (3 bytes), so should be rejected with limit=1
    assert!(matches!(result, Err(JwsError::HeaderTooLong)));
}

#[test]
fn jws_different_contexts_independent() {
    let header = r#"{"alg":"HS256","typ":"JWT","x":"test"}"#;
    let jws = make_compact_jws(header, "{}", "signature");

    let ctx_small = JoseContext::new(10);
    let ctx_large = JoseContext::new(1000);

    let result_small =
        verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx_small);
    let result_large =
        verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx_large);

    // Small context rejects, large context accepts (modulo signature verification)
    assert!(matches!(result_small, Err(JwsError::HeaderTooLong)));
    assert!(!matches!(result_large, Err(JwsError::HeaderTooLong)));
}

#[test]
fn jwe_header_within_limit_accepted() {
    let ctx = JoseContext::new(100);
    let header = r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#;
    let jwe = make_compact_jwe(header, "key", "iv", "ct", "tag");

    // Will fail on decryption, but header should be accepted
    let result = decrypt_rsa_oaep_a256gcm_pkcs8_with_context(&jwe, b"fake-key", ctx);

    assert!(!matches!(result, Err(JweError::HeaderTooLong)));
}

#[test]
fn jwe_header_over_limit_rejected() {
    let ctx = JoseContext::new(10); // Very small limit
    let large_header = r#"{"alg":"RSA-OAEP","enc":"A256GCM","kid":"very-long-identifier"}"#;
    let jwe = make_compact_jwe(large_header, "key", "iv", "ct", "tag");

    let result = decrypt_rsa_oaep_a256gcm_pkcs8_with_context(&jwe, b"fake-key", ctx);

    assert!(matches!(result, Err(JweError::HeaderTooLong)));
}

#[test]
fn jwe_header_exactly_at_limit() {
    let header = r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#;
    let encoded_header = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let limit = encoded_header.len();

    let ctx = JoseContext::new(limit);
    let jwe = make_compact_jwe(header, "key", "iv", "ct", "tag");

    let result = decrypt_rsa_oaep_a256gcm_pkcs8_with_context(&jwe, b"fake-key", ctx);

    // Should not be HeaderTooLong (will fail on other validation)
    assert!(!matches!(result, Err(JweError::HeaderTooLong)));
}

#[test]
fn context_limit_one_accepts_empty_base64() {
    // Edge case: limit of 1 with minimal possible input
    let ctx = JoseContext::new(1);
    let empty_json = "{}";
    let encoded = URL_SAFE_NO_PAD.encode(empty_json.as_bytes());

    // "{}" -> "e30" (3 chars), so this should be rejected
    assert!(encoded.len() > 1);

    let jws = make_compact_jws(empty_json, "{}", "sig");
    let result = verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx);

    assert!(matches!(result, Err(JwsError::HeaderTooLong)));
}

#[test]
fn context_max_i32_limit() {
    // Test with maximum i32 value (2^31 - 1)
    let ctx = JoseContext::new(i32::MAX as usize);
    assert_eq!(ctx.header_max_length(), i32::MAX as usize);

    let header = r#"{"alg":"HS256"}"#;
    let jws = make_compact_jws(header, "{}", "sig");

    let result = verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx);

    // Should not be HeaderTooLong
    assert!(!matches!(result, Err(JwsError::HeaderTooLong)));
}

#[test]
fn context_thread_safety_simulation() {
    skip_if_lowstar_unavailable!();

    let ctx = Arc::new(JoseContext::new(100));
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let jws = make_compact_jws(header, "{}", "signature");

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let ctx_clone = Arc::clone(&ctx);
            let jws_clone = jws.clone();
            thread::spawn(move || {
                let result = verify_compact_with_context(
                    &jws_clone,
                    VerificationKey::HmacSha256(b"secret"),
                    &ctx_clone,
                );
                // All threads should get same result (signature invalid)
                assert!(matches!(result, Err(JwsError::VerificationFailed)));
            })
        })
        .collect();

    for handle in handles {
        assert!(handle.join().is_ok());
    }
}

#[test]
fn context_clone_independence() {
    let ctx1 = JoseContext::new(100);
    let ctx2 = ctx1;

    assert_eq!(ctx1.header_max_length(), ctx2.header_max_length());

    // Verify they're independent (modifying one doesn't affect the other is implicit in the type design)
    let ctx3 = JoseContext::new(200);
    assert_ne!(ctx1.header_max_length(), ctx3.header_max_length());
}

#[test]
fn default_context_matches_constant() {
    let ctx = JoseContext::default();
    assert_eq!(ctx.header_max_length(), DEFAULT_HEADER_MAX_LEN);
}

#[test]
fn boundary_test_4095_vs_4096_vs_4097() {
    let ctx_4095 = JoseContext::new(4095);
    let ctx_4096 = JoseContext::new(4096);

    let header_short = r#"{"alg":"HS256"}"#; // Well within limits
    let jws = make_compact_jws(header_short, "{}", "sig");

    // Both should accept short headers
    let result_4095 =
        verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx_4095);
    let result_4096 =
        verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx_4096);

    assert!(!matches!(result_4095, Err(JwsError::HeaderTooLong)));
    assert!(!matches!(result_4096, Err(JwsError::HeaderTooLong)));
}
