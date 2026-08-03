use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use ffi::{verify_dpop, verify_dpop_with_iat_window, DpopVerification};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const ACCESS_TOKEN: &str = "access_example_token";

fn compute_ath(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn to_iat(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn make_proof(method: &str, uri: &str, iat: i64, jti: &str) -> String {
    make_proof_extended(method, uri, iat, jti, Some("dpop+jwt"), None, None)
}

fn make_proof_extended(
    method: &str,
    uri: &str,
    iat: i64,
    jti: &str,
    typ: Option<&str>,
    ath: Option<&str>,
    nonce: Option<&str>,
) -> String {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let mut header_map = Map::new();
    header_map.insert("alg".to_string(), Value::String("EdDSA".to_string()));
    let mut jwk_map = Map::new();
    jwk_map.insert("kty".to_string(), Value::String("OKP".to_string()));
    jwk_map.insert("crv".to_string(), Value::String("Ed25519".to_string()));
    jwk_map.insert(
        "x".to_string(),
        Value::String(URL_SAFE_NO_PAD.encode(verifying_key.as_bytes())),
    );
    header_map.insert("jwk".to_string(), Value::Object(jwk_map));
    if let Some(value) = typ {
        header_map.insert("typ".to_string(), Value::String(value.to_string()));
    }
    let header_json = Value::Object(header_map);

    let mut payload_map = Map::new();
    payload_map.insert("htm".to_string(), Value::String(method.to_string()));
    payload_map.insert("htu".to_string(), Value::String(uri.to_string()));
    payload_map.insert("iat".to_string(), Value::Number(iat.into()));
    payload_map.insert("jti".to_string(), Value::String(jti.to_string()));
    if let Some(value) = ath {
        payload_map.insert("ath".to_string(), Value::String(value.to_string()));
    }
    if let Some(value) = nonce {
        payload_map.insert("nonce".to_string(), Value::String(value.to_string()));
    }
    let payload_json = Value::Object(payload_map);

    let Ok(header_json) = serde_json::to_string(&header_json) else {
        return String::new();
    };
    let Ok(payload_json) = serde_json::to_string(&payload_json) else {
        return String::new();
    };

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

#[test]
fn valid_proof_is_accepted() {
    let now = 1_700_000_000u64;
    let proof = make_proof(
        "GET",
        "https://example.com/resource",
        to_iat(now),
        "test-jti",
    );
    let res = verify_dpop(&proof, "GET", "https://example.com/resource", now, None);
    assert_eq!(
        res,
        Some(DpopVerification {
            jti: "test-jti".to_string(),
            nonce: None,
        })
    );
}

#[test]
fn request_uri_query_is_ignored_for_htu_comparison() {
    let now = 1_700_000_000u64;
    let proof = make_proof(
        "GET",
        "https://example.com/resource",
        to_iat(now),
        "query-ignored-jti",
    );
    let res = verify_dpop(
        &proof,
        "GET",
        "https://example.com/resource?x=1&y=2",
        now,
        None,
    );
    assert_eq!(
        res,
        Some(DpopVerification {
            jti: "query-ignored-jti".to_string(),
            nonce: None,
        })
    );
}

#[test]
fn htu_with_query_is_rejected() {
    let now = 1_700_000_000u64;
    let proof = make_proof(
        "GET",
        "https://example.com/resource?x=1",
        to_iat(now),
        "htu-has-query",
    );
    assert!(verify_dpop(&proof, "GET", "https://example.com/resource", now, None).is_none());
}

#[test]
fn tampered_signature_is_rejected() {
    let now = 1_700_000_000u64;
    let proof = make_proof(
        "GET",
        "https://example.com/resource",
        to_iat(now),
        "test-jti",
    );
    let mut parts: Vec<String> = proof.split('.').map(str::to_owned).collect();
    let sig_result = URL_SAFE_NO_PAD.decode(&parts[2]);
    assert!(sig_result.is_ok(), "signature must decode");
    let Ok(mut sig_bytes) = sig_result else {
        return;
    };
    sig_bytes[0] ^= 0x01;
    parts[2] = URL_SAFE_NO_PAD.encode(sig_bytes);
    let tampered = parts.join(".");
    assert!(verify_dpop(&tampered, "GET", "https://example.com/resource", now, None).is_none());
}

#[test]
fn wrong_method_is_rejected() {
    let now = 1_700_000_000u64;
    let proof = make_proof(
        "GET",
        "https://example.com/resource",
        to_iat(now),
        "test-jti",
    );
    assert!(verify_dpop(&proof, "POST", "https://example.com/resource", now, None).is_none());
}

#[test]
fn expired_proof_is_rejected() {
    let now = 1_700_000_000u64;
    // Create a proof with an iat well outside the allowed ±300s window.
    let proof = make_proof(
        "GET",
        "https://example.com/resource",
        to_iat(now - 1_000),
        "expired-jti",
    );
    assert!(verify_dpop(&proof, "GET", "https://example.com/resource", now, None).is_none());
}

#[test]
fn future_dated_proof_is_rejected() {
    let now = 1_700_000_000u64;
    let proof = make_proof(
        "GET",
        "https://example.com/resource",
        to_iat(now + 1_000),
        "future-jti",
    );
    assert!(verify_dpop(&proof, "GET", "https://example.com/resource", now, None).is_none());
}

#[test]
fn configured_iat_window_is_enforced() {
    let now = 1_700_000_000u64;
    let proof = make_proof(
        "GET",
        "https://example.com/resource",
        to_iat(now - 45),
        "custom-window-jti",
    );

    assert!(verify_dpop(&proof, "GET", "https://example.com/resource", now, None).is_some());
    assert!(
        verify_dpop_with_iat_window(&proof, "GET", "https://example.com/resource", now, None, 30,)
            .is_none(),
        "operator-selected iat window must narrow acceptance"
    );
}

#[test]
fn missing_typ_is_rejected() {
    let now = 1_700_000_000u64;
    let proof = make_proof_extended(
        "GET",
        "https://example.com/resource",
        to_iat(now),
        "missing-typ-jti",
        None,
        None,
        None,
    );
    assert!(verify_dpop(&proof, "GET", "https://example.com/resource", now, None).is_none());
}

#[test]
fn incorrect_typ_is_rejected() {
    let now = 1_700_000_000u64;
    let proof = make_proof_extended(
        "GET",
        "https://example.com/resource",
        to_iat(now),
        "wrong-typ-jti",
        Some("jwt"),
        None,
        None,
    );
    assert!(verify_dpop(&proof, "GET", "https://example.com/resource", now, None).is_none());
}

#[test]
fn missing_jti_claim_is_rejected() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "dpop+jwt",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
        }
    });
    let payload = serde_json::json!({
        "htm": "GET",
        "htu": "https://example.com/resource",
        "iat": 1_700_000_000i64,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header JSON"));
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload JSON"));
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_b64 = URL_SAFE_NO_PAD.encode(signing_key.sign(signing_input.as_bytes()).to_bytes());
    let proof = format!("{signing_input}.{sig_b64}");

    assert!(verify_dpop(
        &proof,
        "GET",
        "https://example.com/resource",
        1_700_000_000,
        None
    )
    .is_none());
}

#[test]
fn ath_matching_passes() {
    let now = 1_700_000_000u64;
    let expected = compute_ath(ACCESS_TOKEN);
    let proof = make_proof_extended(
        "GET",
        "https://example.com/resource",
        to_iat(now),
        "ath-pass",
        Some("dpop+jwt"),
        Some(&expected),
        None,
    );
    let res = verify_dpop(
        &proof,
        "GET",
        "https://example.com/resource",
        now,
        Some(&expected),
    );
    assert_eq!(
        res,
        Some(DpopVerification {
            jti: "ath-pass".to_string(),
            nonce: None,
        })
    );
}

#[test]
fn ath_missing_but_expected_fails() {
    let now = 1_700_000_000u64;
    let expected = compute_ath(ACCESS_TOKEN);
    let proof = make_proof(
        "GET",
        "https://example.com/resource",
        to_iat(now),
        "ath-missing",
    );
    assert!(verify_dpop(
        &proof,
        "GET",
        "https://example.com/resource",
        now,
        Some(&expected)
    )
    .is_none());
}

#[test]
fn ath_mismatch_is_rejected() {
    let now = 1_700_000_000u64;
    let expected = compute_ath(ACCESS_TOKEN);
    let wrong = compute_ath("other_token");
    let proof = make_proof_extended(
        "GET",
        "https://example.com/resource",
        to_iat(now),
        "ath-bad",
        Some("dpop+jwt"),
        Some(&wrong),
        None,
    );
    assert!(verify_dpop(
        &proof,
        "GET",
        "https://example.com/resource",
        now,
        Some(&expected)
    )
    .is_none());
}

#[test]
fn nonce_is_returned_in_verified_proof() {
    let now = 1_700_000_000u64;
    let proof = make_proof_extended(
        "POST",
        "https://example.com/token",
        to_iat(now),
        "nonce-jti",
        Some("dpop+jwt"),
        None,
        Some("server-nonce"),
    );

    let res = verify_dpop(&proof, "POST", "https://example.com/token", now, None);

    assert_eq!(
        res,
        Some(DpopVerification {
            jti: "nonce-jti".to_string(),
            nonce: Some("server-nonce".to_string()),
        })
    );
}

#[test]
fn duplicate_nonce_claim_is_rejected() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "dpop+jwt",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
        }
    });
    let header_bytes = serde_json::to_vec(&header).expect("header should serialize");
    let header_b64 = URL_SAFE_NO_PAD.encode(header_bytes);
    let payload_b64 = URL_SAFE_NO_PAD.encode(br#"{"htm":"POST","htu":"https://example.com/token","iat":1700000000,"jti":"dup","nonce":"one","nonce":"two"}"#);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_b64 = URL_SAFE_NO_PAD.encode(signing_key.sign(signing_input.as_bytes()).to_bytes());
    let proof = format!("{signing_input}.{sig_b64}");

    assert!(verify_dpop(
        &proof,
        "POST",
        "https://example.com/token",
        1_700_000_000,
        None
    )
    .is_none());
}
