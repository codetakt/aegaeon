//! ID Token verification for the explicitly selected RS256 consumer profile.
use crate::profile::{sha256, ProfileSupply};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
    Algorithm, DecodingKey, Validation,
};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct IdClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    iat: u64,
    nbf: Option<u64>,
    azp: Option<String>,
    nonce: String,
    at_hash: Option<String>,
    c_hash: Option<String>,
}

fn oidc_hash(value: &str) -> String {
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(&Sha256::digest(value.as_bytes())[..16])
}

impl IdClaims {
    fn validate(
        &self,
        supply: &ProfileSupply,
        nonce: &str,
        now: u64,
        access_token: &str,
        code: &str,
    ) -> Result<()> {
        ensure!(
            self.iss == supply.issuer && self.sub == supply.subject && !self.sub.is_empty(),
            "ID Token issuer/subject mismatch"
        );
        let audiences: &[String] = match &self.aud {
            Audience::Single(value) => std::slice::from_ref(value),
            Audience::Multiple(values) => values,
        };
        let unique: std::collections::BTreeSet<_> = audiences.iter().collect();
        ensure!(
            !audiences.is_empty()
                && unique.len() == audiences.len()
                && audiences.iter().all(|v| !v.is_empty())
                && audiences.contains(&supply.client_id),
            "ID Token audience mismatch"
        );
        ensure!(
            (audiences.len() <= 1 || self.azp.as_deref() == Some(&supply.client_id))
                && self.azp.as_deref().is_none_or(|v| v == supply.client_id),
            "ID Token authorized party mismatch"
        );
        ensure!(self.nonce == nonce, "ID Token nonce mismatch");
        ensure!(
            self.exp > now
                && self.exp > self.iat
                && self.iat <= now.saturating_add(60)
                && self
                    .nbf
                    .is_none_or(|v| v <= now.saturating_add(60) && v < self.exp),
            "ID Token time validation failed"
        );
        ensure!(
            self.at_hash
                .as_ref()
                .is_none_or(|v| v == &oidc_hash(access_token))
                && self.c_hash.as_ref().is_none_or(|v| v == &oidc_hash(code)),
            "ID Token token/code hash mismatch"
        );
        Ok(())
    }
}

pub fn verify_id_token(
    token: &str,
    jwks_bytes: &[u8],
    supply: &ProfileSupply,
    nonce: &str,
    access_token: &str,
    code: &str,
) -> Result<(String, String)> {
    ensure!(
        supply.id_token_alg.as_deref() == Some("RS256"),
        "unsupported ID Token algorithm profile"
    );
    let header = decode_header(token).context("invalid ID Token JOSE header")?;
    ensure!(
        header.alg == Algorithm::RS256,
        "ID Token algorithm differs from approved profile"
    );
    let raw_header =
        URL_SAFE_NO_PAD.decode(token.split('.').next().context("missing ID Token header")?)?;
    let raw: serde_json::Value = serde_json::from_slice(&raw_header)?;
    for field in ["crit", "jku", "jwk", "x5u", "b64"] {
        ensure!(
            raw.get(field).is_none(),
            "unsupported ID Token JOSE extension"
        );
    }
    let kid = header
        .kid
        .as_deref()
        .filter(|v| !v.is_empty())
        .context("missing ID Token kid")?;
    let jwks: JwkSet = serde_json::from_slice(jwks_bytes).context("invalid issuer JWKS")?;
    let matches: Vec<_> = jwks
        .keys
        .iter()
        .filter(|j| j.common.key_id.as_deref() == Some(kid))
        .collect();
    ensure!(
        matches.len() == 1,
        "missing or ambiguous ID Token signing key"
    );
    let key = matches[0];
    ensure!(
        key.common
            .key_algorithm
            .is_none_or(|v| v == KeyAlgorithm::RS256)
            && key
                .common
                .public_key_use
                .as_ref()
                .is_none_or(|v| *v == PublicKeyUse::Signature)
            && key
                .common
                .key_operations
                .as_ref()
                .is_none_or(|v| v.contains(&KeyOperations::Verify)),
        "JWKS signing key profile mismatch"
    );
    let AlgorithmParameters::RSA(rsa) = &key.algorithm else {
        anyhow::bail!("RS256 requires an RSA public key");
    };
    let modulus = URL_SAFE_NO_PAD.decode(&rsa.n)?;
    let leading = modulus
        .iter()
        .position(|v| *v != 0)
        .context("empty RSA modulus")?;
    let bits = (modulus.len() - leading - 1) * 8 + (8 - modulus[leading].leading_zeros() as usize);
    ensure!(bits >= 2048, "RSA signing key is smaller than 2048 bits");
    let raw_jwks: serde_json::Value = serde_json::from_slice(jwks_bytes)?;
    for jwk in raw_jwks["keys"].as_array().context("missing JWKS keys")? {
        for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            ensure!(
                jwk.get(field).is_none(),
                "issuer JWKS contains private key material"
            );
        }
    }
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&supply.issuer]);
    validation.set_audience(&[&supply.client_id]);
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "iat"]);
    validation.leeway = 0;
    validation.validate_nbf = true;
    let claims = decode::<IdClaims>(token, &DecodingKey::from_jwk(key)?, &validation)
        .context("ID Token signature/claims verification failed")?
        .claims;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("host clock predates Unix epoch")?
        .as_secs();
    claims.validate(supply, nonce, now, access_token, code)?;
    Ok((claims.sub, sha256(jwks_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn supply() -> ProfileSupply {
        serde_json::from_value(serde_json::json!({"issuer":"https://issuer.example.test",
            "environment_id":"e","configuration_version_id":"v","oauth_profile_id":"p","activation":"ACTIVE",
            "client_id":"client","redirect_uri":"https://client.example.test/cb","client_auth":"client_secret_basic",
            "scope":"openid","subject":"subject","sender_policy":"dpop","par_policy":"required",
            "id_token_alg":"RS256"})).unwrap()
    }
    #[test]
    fn id_token_claim_bindings_reject_wrong_nonce_party_subject_and_time() {
        let mut claims: IdClaims = serde_json::from_value(serde_json::json!({"iss":"https://issuer.example.test",
            "sub":"subject","aud":["client","other"],"azp":"client","nonce":"nonce","iat":100,"exp":300})).unwrap();
        assert!(claims
            .validate(&supply(), "nonce", 200, "token", "code")
            .is_ok());
        assert!(claims
            .validate(&supply(), "wrong", 200, "token", "code")
            .is_err());
        claims.azp = None;
        assert!(claims
            .validate(&supply(), "nonce", 200, "token", "code")
            .is_err());
        claims.azp = Some("client".into());
        claims.sub = "other".into();
        assert!(claims
            .validate(&supply(), "nonce", 200, "token", "code")
            .is_err());
        claims.sub = "subject".into();
        assert!(claims
            .validate(&supply(), "nonce", 300, "token", "code")
            .is_err());
        claims.iat = 261;
        assert!(claims
            .validate(&supply(), "nonce", 200, "token", "code")
            .is_err());
        claims.iat = 100;
        claims.at_hash = Some("wrong".into());
        assert!(claims
            .validate(&supply(), "nonce", 200, "token", "code")
            .is_err());
    }

    #[test]
    fn rs256_signature_jwks_algorithm_and_nonce_are_verified_before_consumption() {
        use std::{fs, process::Command};
        let directory =
            std::env::temp_dir().join(format!("aegaeon-loadtest-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let key = directory.join("key.pem");
        let generated = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .output()
            .unwrap();
        assert!(generated.status.success());
        let modulus = Command::new("openssl")
            .args(["rsa", "-modulus", "-noout", "-in"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(modulus.status.success());
        let hex = String::from_utf8(modulus.stdout).unwrap();
        let hex = hex.trim().strip_prefix("Modulus=").unwrap();
        let bytes: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let jwks = serde_json::to_vec(
            &serde_json::json!({"keys":[{"kty":"RSA","kid":"signing","alg":"RS256","use":"sig",
            "n":URL_SAFE_NO_PAD.encode(bytes),"e":"AQAB"}]}),
        )
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({"iss":"https://issuer.example.test","sub":"subject","aud":"client","nonce":"nonce",
            "iat":now,"exp":now+300,"at_hash":oidc_hash("token"),"c_hash":oidc_hash("code")});
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some("signing".into());
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(&fs::read(key).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_id_token(&token, &jwks, &supply(), "nonce", "token", "code")
                .unwrap()
                .0,
            "subject"
        );
        assert!(verify_id_token(&token, &jwks, &supply(), "wrong", "token", "code").is_err());
        assert!(verify_id_token(&token, &jwks, &supply(), "nonce", "wrong", "code").is_err());
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
        parts[2].replace_range(..1, replacement);
        assert!(
            verify_id_token(&parts.join("."), &jwks, &supply(), "nonce", "token", "code").is_err()
        );
        let hmac = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"key-confusion-probe"),
        )
        .unwrap();
        assert!(verify_id_token(&hmac, &jwks, &supply(), "nonce", "token", "code").is_err());
        assert!(verify_id_token(
            &token,
            b"{\"keys\":[]}",
            &supply(),
            "nonce",
            "token",
            "code"
        )
        .is_err());
    }
}
