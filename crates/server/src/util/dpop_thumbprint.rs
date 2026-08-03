#[cfg(test)]
use super::json_admission::decode_compact_jwt_header_value_without_duplicate_keys;
use super::json_admission::decode_compact_jwt_header_value_without_duplicate_keys_with_max_len;
use base64::Engine;
use std::collections::BTreeMap;

#[cfg(test)]
#[must_use]
pub fn compute_dpop_jkt_from_proof(proof: &str) -> Option<String> {
    let header_v = decode_compact_jwt_header_value_without_duplicate_keys(proof).ok()?;
    compute_dpop_jkt_from_admitted_header(&header_v)
}

#[must_use]
pub fn compute_dpop_jkt_from_proof_with_max_len(
    proof: &str,
    jose_header_max_len: usize,
) -> Option<String> {
    let header_v = decode_compact_jwt_header_value_without_duplicate_keys_with_max_len(
        proof,
        jose_header_max_len,
    )
    .ok()?;
    compute_dpop_jkt_from_admitted_header(&header_v)
}

fn compute_dpop_jkt_from_admitted_header(header_v: &serde_json::Value) -> Option<String> {
    let jwk = header_v.get("jwk")?.as_object()?;
    let kty = jwk.get("kty")?.as_str()?;
    // RFC 7638 JWK Thumbprint. This helper intentionally admits only the DPoP
    // curves supported by the verifier path: EC P-256 and OKP Ed25519.
    match kty {
        "EC" => {
            let crv = jwk.get("crv")?.as_str()?;
            if crv != "P-256" {
                return None;
            }
            let x = jwk_coordinate(jwk.get("x")?.as_str()?, 32)?;
            let y = jwk_coordinate(jwk.get("y")?.as_str()?, 32)?;
            let canonical =
                canonical_thumbprint_json([("crv", crv), ("kty", "EC"), ("x", x), ("y", y)])?;
            let digest = aegaeon_crypto::hash::sha256_digest(&canonical);
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
        }
        "OKP" => {
            let crv = jwk.get("crv")?.as_str()?;
            if crv != "Ed25519" {
                return None;
            }
            let x = jwk_coordinate(jwk.get("x")?.as_str()?, 32)?;
            let canonical = canonical_thumbprint_json([("crv", crv), ("kty", "OKP"), ("x", x)])?;
            let digest = aegaeon_crypto::hash::sha256_digest(&canonical);
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
        }
        _ => None,
    }
}

fn jwk_coordinate(value: &str, expected_len: usize) -> Option<&str> {
    let valid_chars = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if value.is_empty() || !valid_chars {
        return None;
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()?;
    (decoded.len() == expected_len).then_some(value)
}

fn canonical_thumbprint_json<'a>(
    members: impl IntoIterator<Item = (&'static str, &'a str)>,
) -> Option<Vec<u8>> {
    let canonical: BTreeMap<&'static str, &'a str> = members.into_iter().collect();
    let bytes = serde_json::to_vec(&canonical).ok()?;
    bytes.is_ascii().then_some(bytes)
}

const JWK_THUMBPRINT_URI_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

/// Construct an RFC 9278 JWK thumbprint URI from a thumbprint value (jkt).
#[must_use]
pub fn jwk_thumbprint_uri_from_jkt(jkt: &str) -> String {
    format!("{JWK_THUMBPRINT_URI_PREFIX}{jkt}")
}

#[must_use]
pub fn jwk_thumbprint_matches(expected: &str, presented: &str) -> bool {
    if expected == presented {
        return true;
    }
    match (
        normalize_jwk_thumbprint(expected),
        normalize_jwk_thumbprint(presented),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn normalize_jwk_thumbprint(value: &str) -> Option<String> {
    if let Some(rest) = value.strip_prefix(JWK_THUMBPRINT_URI_PREFIX) {
        return if is_base64url_token(rest) {
            Some(rest.to_string())
        } else {
            None
        };
    }
    if is_base64url_token(value) {
        return Some(value.to_string());
    }
    None
}

fn is_base64url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}
