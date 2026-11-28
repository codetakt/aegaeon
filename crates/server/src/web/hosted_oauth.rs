//! The confidential invitation client. Its credentials and per-flow key never
//! enter a browser redirect. All requests use fixed issuer endpoints over TLS.
mod protocol;
mod transport;

use crate::organizations::operators::mutations::delivery::registration::{
    hosted_client_identifier, HOSTED_CALLBACK as CALLBACK, HOSTED_CLIENT_PREFIX,
};
use aegaeon_crypto::{hash::sha256_digest, rand::fill_random, signing::Ed25519SigningKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
pub(super) use protocol::account;
pub(crate) use protocol::{exchange, post, redeem, revoke, Operation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;
use uuid::Uuid;

const SOURCE_SCOPES: &str = "openid read offline_access";
pub(crate) use crate::organizations::invitations::recipient::PRIVILEGE as RECIPIENT_SCOPE;

/// Fixed refusal classes. Protocol errors never contain a remote response,
/// an HTTP URL with a query, a credential, or a signed assertion.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum Error {
    #[error("invitation authority is unavailable")]
    Refused,
    #[error("the invitation requires a fresh authorization")]
    Expired,
    #[error("the issuer is unavailable")]
    Unavailable,
}

pub(crate) fn domain_for_client(id: &str) -> Option<Uuid> {
    let value = id.strip_prefix(HOSTED_CLIENT_PREFIX)?;
    let domain = Uuid::parse_str(value).ok()?;
    (!domain.is_nil() && domain.to_string() == value).then_some(domain)
}

fn now() -> Result<i64, Error> {
    crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or(Error::Unavailable)
}

fn endpoint(issuer: &str, path: &str) -> Result<String, Error> {
    let url = Url::parse(issuer).map_err(|_| Error::Refused)?;
    if url.scheme() != "https" || url.origin().ascii_serialization() != issuer {
        return Err(Error::Refused);
    }
    Ok(format!("{issuer}{path}"))
}

fn random() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes).map_err(|_| Error::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofKey {
    // PKCS#8 is only ever persisted inside the encrypted flow.
    private: Vec<u8>,
}
impl Drop for ProofKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.private);
    }
}

impl ProofKey {
    fn public(&self) -> Result<(Ed25519SigningKey, Value), Error> {
        let key = Ed25519SigningKey::from_pkcs8(&self.private).map_err(|_| Error::Unavailable)?;
        let x = key.public_key_bytes().map_err(|_| Error::Unavailable)?;
        Ok((
            key,
            json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(x)}),
        ))
    }
    fn jkt(&self) -> Result<String, Error> {
        let (_, jwk) = self.public()?;
        let x = jwk["x"].as_str().ok_or(Error::Unavailable)?;
        // RFC 7638 uses lexicographic order independent of serde map features.
        let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
        Ok(URL_SAFE_NO_PAD.encode(sha256_digest(canonical.as_bytes())))
    }
    fn proof(&self, url: &str, token: Option<&str>, nonce: Option<&str>) -> Result<String, Error> {
        let (key, jwk) = self.public()?;
        let header = json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":jwk});
        let mut claims = json!({"htm":"POST","htu":url,"iat":now()?,"jti":random()?});
        if let Some(token) = token {
            claims["ath"] = json!(URL_SAFE_NO_PAD.encode(sha256_digest(token.as_bytes())));
        }
        if let Some(nonce) = nonce {
            claims["nonce"] = json!(nonce);
        }
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).map_err(|_| Error::Unavailable)?)
        ))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authorization {
    pub state: String,
    pub issuer: String,
    pub domain: Uuid,
    pub started_at: i64,
    pub deadline: i64,
    verifier: String,
    nonce: String,
    key: ProofKey,
}
impl Authorization {
    pub(crate) fn begin(issuer: &str, domain: Uuid, deadline: i64) -> Result<Self, Error> {
        endpoint(issuer, CALLBACK)?;
        let started_at = now()?;
        if domain.is_nil() || deadline <= started_at || deadline > started_at.saturating_add(1800) {
            return Err(Error::Expired);
        }
        let key = Ed25519SigningKey::generate().map_err(|_| Error::Unavailable)?;
        Ok(Self {
            state: random()?,
            issuer: issuer.into(),
            domain,
            started_at,
            deadline,
            verifier: random()?,
            nonce: random()?,
            key: ProofKey { private: key.pkcs8 },
        })
    }
    fn client_id(&self) -> String {
        hosted_client_identifier(self.domain)
    }
    fn challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(sha256_digest(self.verifier.as_bytes()))
    }
    pub(crate) fn url(&self) -> Result<String, Error> {
        let mut url =
            Url::parse(&endpoint(&self.issuer, "/authorize")?).map_err(|_| Error::Refused)?;
        url.query_pairs_mut().extend_pairs([
            ("client_id", self.client_id().as_str()),
            ("iss", self.issuer.as_str()),
            ("response_type", "code"),
            ("response_mode", "query"),
            ("redirect_uri", endpoint(&self.issuer, CALLBACK)?.as_str()),
            ("scope", SOURCE_SCOPES),
            ("resource", endpoint(&self.issuer, "/userinfo")?.as_str()),
            ("state", &self.state),
            ("nonce", &self.nonce),
            ("code_challenge_method", "S256"),
            ("code_challenge", &self.challenge()),
            ("dpop_jkt", &self.key.jkt()?),
            ("prompt", "login consent"),
            ("max_age", "0"),
        ]);
        Ok(url.into())
    }
    pub(super) fn matches(
        &self,
        req: &crate::authcode::types::AuthorizationRequest,
        issuer: &str,
        auth_time: i64,
    ) -> Result<(), Error> {
        let current = now()?;
        if current >= self.deadline
            || auth_time < self.started_at
            || auth_time > current
            || current - auth_time > 300
            || issuer != self.issuer
            || req.iss.as_deref() != Some(issuer)
            || req.client_id != self.client_id()
            || req.scope.as_deref() != Some(SOURCE_SCOPES)
            || req.resource.as_deref() != Some(endpoint(issuer, "/userinfo")?.as_str())
            || req.max_age != Some(0)
            || req.response_type != "code"
            || req.authorization_details.is_some()
            || req.redirect_uri.as_deref() != Some(endpoint(issuer, CALLBACK)?.as_str())
            || req.state.as_deref() != Some(&self.state)
            || req.nonce.as_deref() != Some(&self.nonce)
            || req.code_challenge.as_deref() != Some(&self.challenge())
            || req.code_challenge_method.as_deref() != Some("S256")
            || req.dpop_jkt.as_ref().map(|v| v.as_str()) != Some(&self.key.jkt()?)
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Grant {
    pub subject: String,
    pub user_id: Uuid,
    pub account: String,
    pub sid: String,
    pub auth_time: i64,
    pub parent_expires_at: i64,
    pub cleanup: Cleanup,
    parent: String,
    key: ProofKey,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cleanup {
    pub client_id: String,
    pub deadline: i64,
    issuer: String,
    refresh: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Recipient {
    pub expires_at: i64,
    access: String,
}

#[cfg(test)]
mod tests;
