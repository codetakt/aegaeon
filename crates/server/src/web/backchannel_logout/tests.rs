use super::*;
use crate::oidc::OidcSigningKey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;

type TestResult<T = ()> = anyhow::Result<T>;
const PRIVATE_PEM: &str = include_str!("../../../tests/fixtures/rsa2048-private.pk8.pem");
const KID: &str = "logout-signing-key";
const ISSUER: &str = "https://issuer.example";

mod delivery;
#[cfg(feature = "kms-aws")]
mod kms;
mod profile;

fn local_key() -> TestResult<OidcSigningKey> {
    Ok(OidcSigningKey::from_rsa_pem(KID.to_string(), PRIVATE_PEM)?)
}

fn config(signing_key: OidcSigningKey) -> OidcConfig {
    OidcConfig {
        issuer: ISSUER.to_string(),
        id_token_ttl_secs: 3600,
        discovery_enabled: true,
        userinfo_enabled: true,
        logout_enabled: true,
        backchannel_logout_enabled: true,
        logout_session_ttl_secs: 600,
        backchannel_logout_timeout_secs: 2,
        require_nonce: false,
        signing_key,
        request_object_encryption_key: None,
    }
}

fn verify_token(key: &OidcSigningKey, token: &str, typ: &str) -> TestResult<Value> {
    let encoded_header = token
        .split('.')
        .next()
        .ok_or_else(|| anyhow::anyhow!("header"))?;
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded_header)?)?;
    assert_eq!(header, json!({"alg":"RS256", "typ":typ, "kid":KID}));
    let jwks = key.jwks();
    let jwk = jwks.keys.first().ok_or_else(|| anyhow::anyhow!("JWK"))?;
    let modulus = URL_SAFE_NO_PAD.decode(jwk.n.as_deref().ok_or_else(|| anyhow::anyhow!("n"))?)?;
    let exponent = URL_SAFE_NO_PAD.decode(jwk.e.as_deref().ok_or_else(|| anyhow::anyhow!("e"))?)?;
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| anyhow::anyhow!("raw json env guard"))?;
    let payload = aegaeon_jose::verify_compact_with_context(
        token,
        aegaeon_jose::VerificationKey::RsaPkcs1Sha256 {
            modulus: &modulus,
            exponent: &exponent,
        },
        &aegaeon_jose::JoseContext::default(),
    )?;
    Ok(serde_json::from_slice(&payload)?)
}

fn verify_logout(
    key: &OidcSigningKey,
    token: &str,
    audience: &str,
    sub: Option<&str>,
) -> TestResult<Value> {
    let claims = verify_token(key, token, "logout+jwt")?;
    let iat = claims["iat"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("iat"))?;
    let mut expected = json!({
        "iss":ISSUER, "aud":audience, "iat":iat, "exp":iat.checked_add(300),
        "jti":"logout-event", "sid":"session", "events":{BACKCHANNEL_LOGOUT_EVENT_URI:{}}
    });
    if let Some(subject) = sub {
        expected["sub"] = json!(subject);
    }
    assert_eq!(claims, expected); // Exact object also excludes nonce and unexpected claims.
    Ok(claims)
}

struct FixtureTask(tokio::task::JoinHandle<()>);
impl Drop for FixtureTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
