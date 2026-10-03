//! Real Ed25519 signatures exercise both production FFI verification entry points.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use ffi::{verify_dpop, verify_dpop_with_iat_window, DpopVerification};

const NOW: u64 = 1_700_000_000;
const URI: &str = "https://issuer.example/resource";
const PAYLOAD: &str =
    r#"{"htm":"GET","htu":"https://issuer.example/resource","iat":1700000000,"jti":"header-test"}"#;

fn public_key() -> String {
    URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[1u8; 32])
            .verifying_key()
            .as_bytes(),
    )
}

fn header(jwk_extra: &str, header_extra: &str) -> String {
    format!(
        r#"{{"alg":"EdDSA","typ":"dpop+jwt","jwk":{{"kty":"OKP","crv":"Ed25519","x":"{}"{jwk_extra}}}{header_extra}}}"#,
        public_key()
    )
}

fn sign_header(header: &str) -> String {
    // Public deterministic test seed, never a deployed key. Sign the exact raw
    // header bytes so duplicate/escaped names cannot disappear in a JSON map.
    let key = SigningKey::from_bytes(&[1u8; 32]);
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.as_bytes()),
        URL_SAFE_NO_PAD.encode(PAYLOAD.as_bytes())
    );
    let signature = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes());
    format!("{input}.{signature}")
}

fn assert_proof(proof: &str, accepted: bool) {
    let expected = accepted.then(|| DpopVerification {
        jti: "header-test".into(),
        nonce: None,
    });
    assert_eq!(verify_dpop(proof, "GET", URI, NOW, None), expected);
    assert_eq!(
        verify_dpop_with_iat_window(proof, "GET", URI, NOW, None, 30),
        expected
    );
}

fn assert_header(header: &str, accepted: bool) {
    assert_proof(&sign_header(header), accepted);
}

#[test]
fn dpop_public_key_and_noncritical_extensions_are_accepted() {
    for (jwk_extra, header_extra) in [
        ("", ""),
        (
            r#", "kid":"test", "use":"sig", "custom":{"label":true}"#,
            r#", "kid":"header-test", "custom":{"label":true}"#,
        ),
        ("", r#", "b64":true"#),
        ("", r#", "\u006264":true"#),
    ] {
        assert_header(&header(jwk_extra, header_extra), true);
    }
}

#[test]
fn dpop_private_key_member_is_rejected_regardless_of_value() {
    for value in [
        r#""AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE""#,
        r#""malformed""#,
        "null",
        "false",
        "1",
        "[]",
        "{}",
    ] {
        assert_header(&header(&format!(r#", "d":{value}"#), ""), false);
        assert_header(&header(&format!(r#", "\u0064":{value}"#), ""), false);
    }
}

#[test]
fn dpop_every_critical_extension_shape_is_rejected() {
    for value in [
        "null",
        "false",
        "1",
        r#""custom""#,
        "{}",
        "[]",
        "[null]",
        "[1]",
        r#"["custom"]"#,
        r#"["missing"]"#,
        r#"["custom","custom"]"#,
        r#"["alg"]"#,
        r#"["jwk"]"#,
        r#"["typ"]"#,
        r#"["b64"]"#,
    ] {
        assert_header(
            &header(
                "",
                &format!(r#", "custom":true, "b64":true, "crit":{value}"#),
            ),
            false,
        );
    }
    assert_header(
        &header("", r#", "\u0063rit":["custom"], "custom":true"#),
        false,
    );
}

#[test]
fn dpop_unencoded_or_malformed_payload_encoding_is_rejected() {
    for value in ["false", "null", "1", r#""true""#, "[]", "{}"] {
        assert_header(&header("", &format!(r#", "b64":{value}"#)), false);
    }
    assert_header(&header("", r#", "b64":false, "crit":["b64"]"#), false);
}

#[test]
fn dpop_duplicate_header_names_including_escaped_aliases_are_rejected() {
    for extra in [
        r#", "alg":"EdDSA""#.to_owned(),
        r#", "typ":"dpop+jwt""#.to_owned(),
        format!(
            r#", "jwk":{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
            public_key()
        ),
        r#", "\u0061lg":"EdDSA""#.to_owned(),
        r#", "custom":1, "custom":2"#.to_owned(),
        r#", "custom":1, "\u0063ustom":1"#.to_owned(),
        r#", "b64":true, "b64":true"#.to_owned(),
    ] {
        assert_header(&header("", &extra), false);
    }
}

#[test]
fn dpop_duplicate_jwk_names_including_escaped_aliases_are_rejected() {
    for extra in [
        r#", "kty":"OKP""#.to_owned(),
        r#", "crv":"Ed25519""#.to_owned(),
        format!(r#", "x":"{}""#, public_key()),
        r#", "\u006bty":"OKP""#.to_owned(),
        r#", "custom":1, "custom":2"#.to_owned(),
        r#", "custom":1, "\u0063ustom":1"#.to_owned(),
    ] {
        assert_header(&header(&extra, ""), false);
    }
}

#[test]
fn dpop_required_header_and_key_types_remain_enforced() {
    let valid = header("", "");
    assert_header(
        &format!(
            r#"["EdDSA",{{"kty":"OKP","crv":"Ed25519","x":"{}"}},"dpop+jwt"]"#,
            public_key()
        ),
        false,
    );
    assert_header(
        &format!(
            r#"{{"alg":"EdDSA","typ":"dpop+jwt","jwk":["OKP","Ed25519","{}"]}}"#,
            public_key()
        ),
        false,
    );
    for (from, to) in [
        (r#""alg":"EdDSA""#, r#""alg":null"#),
        (r#""alg":"EdDSA""#, r#""alg":"HS256""#),
        (r#""typ":"dpop+jwt""#, r#""typ":null"#),
        (r#""typ":"dpop+jwt""#, r#""typ":1"#),
        (r#""kty":"OKP""#, r#""kty":null"#),
        (r#""kty":"OKP""#, r#""kty":"EC""#),
        (r#""crv":"Ed25519""#, r#""crv":null"#),
        (r#""crv":"Ed25519""#, r#""crv":"Ed448""#),
    ] {
        assert_header(&valid.replace(from, to), false);
    }
}

#[test]
fn dpop_allowed_header_does_not_bypass_signature_verification() {
    let proof = sign_header(&header("", r#", "b64":true, "custom":true"#));
    assert_proof(&proof, true);
    let (input, encoded_signature) = proof.rsplit_once('.').expect("compact proof");
    let mut signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .expect("signature");
    signature[0] ^= 1;
    assert_proof(
        &format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)),
        false,
    );
}
