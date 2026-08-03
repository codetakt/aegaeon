use aegaeon_jose::jws::{verify_compact_with_context, JwsError, VerificationKey};
use aegaeon_jose::policy::JoseContext;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

fn make_compact(header: &str, payload: &str, signature: &str) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.as_bytes()),
        URL_SAFE_NO_PAD.encode(signature.as_bytes())
    )
}

#[test]
fn header_length_limit_is_enforced() {
    // Use per-request context API instead of deprecated global settings
    let ctx = JoseContext::new(16);

    let jws = make_compact(
        "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"very-long-kid-value\"}",
        "{}",
        "signature",
    );
    let result = verify_compact_with_context(&jws, VerificationKey::HmacSha256(b"secret"), &ctx);
    assert!(matches!(result, Err(JwsError::HeaderTooLong)));
}
