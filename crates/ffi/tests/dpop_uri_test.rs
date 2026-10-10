//! Signed fixtures exercise URI comparison through both production FFI APIs.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use ffi::{verify_dpop, verify_dpop_with_iat_window, DpopVerification};
use serde_json::json;

const NOW: u64 = 1_700_000_000;

fn signed_proof(uri: &str) -> String {
    // Public deterministic fixture seed, never a deployed key.
    let key = SigningKey::from_bytes(&[2; 32]);
    let header = json!({"alg":"EdDSA", "typ":"dpop+jwt", "jwk": {
        "kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
    }});
    let claims = json!({"htm":"GET", "htu":uri, "iat":NOW, "jti":"uri-test", "nonce":"nonce-test"});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
    )
}

fn assert_proof(proof: &str, request: &str, accepted: bool) {
    let expected = accepted.then(|| DpopVerification {
        jti: "uri-test".into(),
        nonce: Some("nonce-test".into()),
    });
    assert_eq!(
        verify_dpop(proof, "GET", request, NOW, None),
        expected,
        "default window: {request:?}"
    );
    assert_eq!(
        verify_dpop_with_iat_window(proof, "GET", request, NOW, None, 30),
        expected,
        "configured window: {request:?}"
    );
}

fn assert_pair(proof_uri: &str, request: &str, accepted: bool) {
    assert_proof(&signed_proof(proof_uri), request, accepted);
}

#[test]
fn dpop_uri_accepts_http_component_normalization() {
    for (proof, request) in [
        (
            "HTTPS://ISSUER.EXAMPLE/resource",
            "https://issuer.example/resource",
        ),
        (
            "https://issuer.example/resource",
            "HTTPS://ISSUER.EXAMPLE/resource",
        ),
        (
            "https://%49SSUER.example/%7e%41%2d%5f%2E",
            "https://issuer.example/~A-_.",
        ),
        (
            "https://issuer.example/%2f%3f%23%3a%40",
            "https://issuer.example/%2F%3F%23%3A%40",
        ),
        ("https://issuer.example:443/", "https://issuer.example"),
        ("http://issuer.example:00080", "http://issuer.example/"),
        ("https://issuer.example:/", "https://issuer.example:00443"),
        (
            "https://issuer.example:00081/a",
            "https://issuer.example:81/a",
        ),
        ("https://issuer.example:0/", "https://issuer.example:00000/"),
        (
            "https://issuer.example:65535/",
            "https://issuer.example:65535/",
        ),
        (
            "https://[2001:DB8::ABCD]/a",
            "https://[2001:db8::abcd]:443/a",
        ),
        ("https://[::ffff:192.0.2.1]/", "HTTPS://[::FFFF:192.0.2.1]"),
        ("https://[vF.ABC:def!]/", "https://[Vf.abc:DEF!]:/"),
        (
            "https://foo!$&'()*+,;=.example/a:@!$&'()*+,;=",
            "https://FOO!$&'()*+,;=.example/a:@!$&'()*+,;=",
        ),
        ("https://issuer.example%2f/a", "https://ISSUER.EXAMPLE%2F/a"),
    ] {
        assert_pair(proof, request, true);
    }
}

#[test]
fn dpop_uri_removes_dot_segments_without_collapsing_other_segments() {
    for (path, normalized) in [
        ("/a/b/c/./../../g", "/a/g"),
        ("/a/./b/../c", "/a/c"),
        ("/a/%2e/b/%2E%2e/c", "/a/c"),
        ("/a/.%2e/c", "/c"),
        ("/a/%2e./c", "/c"),
        ("/a/b/..", "/a/"),
        ("/a/b/.", "/a/b/"),
        ("/a/../..", "/"),
        ("/../../a", "/a"),
        ("/a//b/./c", "/a//b/c"),
        ("/a//../b", "/a/b"),
        ("//a/../b//", "//b//"),
        ("/a/b/c/../../../g", "/g"),
        ("/a/b/c/../../../../g", "/g"),
        ("/a/b/c/g/../h", "/a/b/c/h"),
        ("/a/b/c/g;x=1/../y", "/a/b/c/y"),
        ("/a/b/c/g;x=1/./y", "/a/b/c/g;x=1/y"),
        ("/a/.../b/..g/g../.g", "/a/.../b/..g/g../.g"),
        ("/a/%252e%252e/b", "/a/%252e%252e/b"),
    ] {
        let raw = format!("https://issuer.example{path}");
        let normalized = format!("https://issuer.example{normalized}");
        assert_pair(&raw, &normalized, true);
        assert_pair(&normalized, &raw, true);
    }
}

#[test]
fn dpop_uri_preserves_significant_distinctions() {
    for (proof, request) in [
        ("https://issuer.example/A", "https://issuer.example/a"),
        ("https://issuer.example/a%2Fb", "https://issuer.example/a/b"),
        ("https://issuer.example/a%3Fb", "https://issuer.example/a?b"),
        ("https://issuer.example/a%23b", "https://issuer.example/a#b"),
        ("https://issuer.example/a%3Ab", "https://issuer.example/a:b"),
        ("https://issuer.example/a%40b", "https://issuer.example/a@b"),
        ("https://issuer.example/a//b", "https://issuer.example/a/b"),
        ("https://issuer.example/a/", "https://issuer.example/a"),
        ("https://issuer.example//", "https://issuer.example/"),
        ("https://issuer.example/a", "http://issuer.example/a"),
        ("https://issuer.example/a", "https://other.example/a"),
        ("https://issuer.example:80/a", "https://issuer.example/a"),
        (
            "https://issuer.example:444/a",
            "https://issuer.example:443/a",
        ),
        ("https://issuer.example./a", "https://issuer.example/a"),
        ("https://127.1/a", "https://127.0.0.1/a"),
        ("https://2130706433/a", "https://127.0.0.1/a"),
        ("https://0177.0.0.1/a", "https://127.0.0.1/a"),
        ("https://0x7f000001/a", "https://127.0.0.1/a"),
        (
            "https://[2001:db8::1]/a",
            "https://[2001:db8:0:0:0:0:0:1]/a",
        ),
        ("https://[2001:0db8::1]/a", "https://[2001:db8::1]/a"),
        ("https://issuer.example%2F/a", "https://issuer.example/a"),
    ] {
        assert_pair(proof, request, false);
    }
}

#[test]
fn dpop_uri_rejects_malformed_input_even_when_identical() {
    for uri in [
        "",
        "/a",
        "//issuer.example/a",
        "ftp://issuer.example/a",
        "https:issuer.example/a",
        "https:///a",
        "https://",
        "https://:443/a",
        "https://user@issuer.example/a",
        "https://user:pass@issuer.example/a",
        "https://issuer.example/a%",
        "https://issuer.example/a%2",
        "https://issuer.example/a%GG",
        "https://issuer%.example/a",
        "https://issuer%0G.example/a",
        " https://issuer.example/a",
        "https://issuer.example/a ",
        "https://issuer.example/\ta",
        "https://issuer.example/\na",
        "https://issuer.example/\0a",
        "https://issuer.example/é",
        "https://é.example/a",
        "https://issuer.example\\a",
        "https://issuer.example/a\\b",
        "https://issuer.example/<a>",
        "https://issuer.example/[a]",
        "https://issuer.example/|a",
        "https://issuer.example:65536/a",
        "https://issuer.example:18446744073709551616/a",
        "https://issuer.example:-1/a",
        "https://issuer.example:+443/a",
        "https://issuer.example:abc/a",
        "https://issuer.example:443:80/a",
        "https://2001:db8::1/a",
        "https://[2001:db8::1/a",
        "https://[2001:db8::1]suffix/a",
        "https://[2001:db8::1]:443:80/a",
        "https://[]/a",
        "https://[not-ip]/a",
        "https://[:::1]/a",
        "https://[::1]]/a",
        "https://[::1%25zone]/a",
        "https://[v.a]/a",
        "https://[vG.a]/a",
        "https://[v1.]/a",
        "https://[v1.%41]/a",
    ] {
        assert_pair(uri, uri, false);
        assert_pair(uri, "https://issuer.example/a", false);
        assert_pair("https://issuer.example/a", uri, false);
    }
}

#[test]
fn dpop_uri_ignores_only_valid_request_query_and_fragment() {
    for request in [
        "https://issuer.example/a?x=1#f",
        "https://issuer.example/a#f?x=1",
        "https://issuer.example/a?",
        "https://issuer.example/a#",
        "https://issuer.example/a?#",
        "HTTPS://ISSUER.EXAMPLE:443/./a?x=%2F/?#f/?",
    ] {
        assert_pair("https://issuer.example/a", request, true);
    }
    for suffix in ["?x=1", "#f", "?", "#", "?#"] {
        assert_pair(
            &format!("https://issuer.example/a{suffix}"),
            "https://issuer.example/a",
            false,
        );
    }
    for suffix in [
        "?%",
        "#%GG",
        "?bad input",
        "#bad\\input",
        "#one#two",
        "?é",
        "?[x]",
    ] {
        assert_pair(
            "https://issuer.example/a",
            &format!("https://issuer.example/a{suffix}"),
            false,
        );
    }
}

#[test]
fn dpop_uri_normalization_does_not_bypass_signature_verification() {
    let proof = signed_proof("HTTPS://ISSUER.EXAMPLE:443/a/../resource");
    let request = "https://issuer.example/resource";
    assert_proof(&proof, request, true);
    let (input, encoded_signature) = proof.rsplit_once('.').expect("compact proof");
    let mut signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .expect("signature");
    signature[0] ^= 1;
    assert_proof(
        &format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)),
        request,
        false,
    );
}
