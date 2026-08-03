use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use super::super::super::validation::runtime_key_bad_request;

pub(super) fn jwt_eddsa_public_jwk(
    kid: &str,
    pkcs8_der: &[u8],
    request_id: &str,
) -> Result<crate::jwk_types::Jwk, Response> {
    let key_pair =
        aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(pkcs8_der).map_err(|_| {
            runtime_key_bad_request(
                request_id,
                "privateKeyPem is not usable as an Ed25519 JWT signing key",
                None,
            )
        })?;
    let public_key = key_pair.public_key_bytes().map_err(|_| {
        runtime_key_bad_request(
            request_id,
            "privateKeyPem produced an invalid Ed25519 public key",
            None,
        )
    })?;
    Ok(crate::jwk_types::Jwk {
        kty: "OKP".to_string(),
        use_: Some("sig".to_string()),
        kid: kid.to_string(),
        alg: Some("EdDSA".to_string()),
        n: None,
        e: None,
        x: Some(URL_SAFE_NO_PAD.encode(public_key)),
        y: None,
        crv: Some("Ed25519".to_string()),
    })
}
