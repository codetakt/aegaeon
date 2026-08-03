use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

mod hash;
mod validation;
#[cfg(test)]
use ffi::id_token::OidcHashError;
use hash::compute_hash;
#[cfg(test)]
use hash::finalize_hash_result;

fn is_https_url(value: &str) -> bool {
    let Ok(parsed) = Url::parse(value) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.host_str().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
}

fn unix_time_now_i64() -> Option<i64> {
    crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|secs| i64::try_from(secs).ok())
}

// Define types locally for OIDC module
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Error {
    InvalidRequest(String),
    InvalidToken,
    InsufficientScope,
    ServerError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidRequest(msg) => write!(f, "Invalid request: {msg}"),
            Error::InvalidToken => write!(f, "Invalid token"),
            Error::InsufficientScope => write!(f, "Insufficient scope"),
            Error::ServerError(msg) => write!(f, "Server error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// ID Token claims per OIDC Core 1.0
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer - REQUIRED
    pub iss: String,

    /// Subject - REQUIRED
    pub sub: String,

    /// Audience - REQUIRED (single string or array)
    pub aud: Audience,

    /// Expiration time - REQUIRED
    pub exp: i64,

    /// Issued at - REQUIRED
    pub iat: i64,

    /// Authentication time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,

    /// Nonce - REQUIRED for implicit flow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Authentication Context Reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,

    /// Authentication Methods References
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,

    /// Authorized party - REQUIRED when multiple audiences
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,

    /// Session ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,

    /// Access token hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,

    /// Code hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_hash: Option<String>,

    /// Not before
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Additional claims
    #[serde(flatten)]
    pub additional_claims: HashMap<String, serde_json::Value>,
}

/// Audience claim (single or multiple)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    #[must_use]
    pub fn contains(&self, client_id: &str) -> bool {
        match self {
            Audience::Single(s) => s == client_id,
            Audience::Multiple(v) => v.contains(&client_id.to_string()),
        }
    }

    #[must_use]
    pub fn is_multiple(&self) -> bool {
        matches!(self, Audience::Multiple(_))
    }
}

/// ID Token structure
pub struct IdToken {
    pub claims: IdTokenClaims,
    pub signing_alg: String,
}

#[derive(Debug, Clone)]
pub struct IdTokenValidationContext<'a> {
    pub client_id: &'a str,
    pub issuer: &'a str,
    pub expected_nonce: Option<&'a str>,
    pub max_age: Option<i64>,
    pub access_token_for_hash: Option<&'a str>,
    pub code_for_hash: Option<&'a str>,
    pub clock_skew: i64,
    pub current_time: Option<i64>,
}

impl<'a> IdTokenValidationContext<'a> {
    #[must_use]
    pub fn new(client_id: &'a str, issuer: &'a str) -> Self {
        Self {
            client_id,
            issuer,
            expected_nonce: None,
            max_age: None,
            access_token_for_hash: None,
            code_for_hash: None,
            clock_skew: 60,
            current_time: None,
        }
    }
}

/// ID Token builder
pub struct IdTokenBuilder {
    claims: IdTokenClaims,
    signing_alg: String,
}

impl IdTokenBuilder {
    fn claims_at(issuer: String, subject: String, client_id: String, now: i64) -> IdTokenClaims {
        IdTokenClaims {
            iss: issuer,
            sub: subject,
            aud: Audience::Single(client_id),
            exp: now.saturating_add(3600), // 1 hour default
            iat: now,
            auth_time: Some(now),
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            sid: None,
            at_hash: None,
            c_hash: None,
            nbf: Some(now),
            jti: None,
            additional_claims: HashMap::new(),
        }
    }

    /// Create new ID token builder, reporting issuer or host-clock failures.
    ///
    /// # Errors
    ///
    /// Returns an error when `issuer` is not an HTTPS issuer URL or the host
    /// clock cannot be represented as a Unix timestamp.
    pub fn try_new(issuer: String, subject: String, client_id: String) -> Result<Self> {
        if !is_https_url(&issuer) {
            return Err(Error::ServerError(
                "OIDC ID token builder requires an https issuer".to_string(),
            ));
        }
        let now = unix_time_now_i64().ok_or_else(|| {
            Error::ServerError("OIDC ID token builder could not read system time".to_string())
        })?;

        Ok(Self {
            claims: Self::claims_at(issuer, subject, client_id, now),
            signing_alg: "RS256".to_string(),
        })
    }

    /// Set expiration time
    #[must_use]
    pub fn expiration(mut self, exp: i64) -> Self {
        self.claims.exp = exp;
        self
    }

    /// Set nonce
    #[must_use]
    pub fn nonce(mut self, nonce: String) -> Self {
        self.claims.nonce = Some(nonce);
        self
    }

    /// Set authentication context reference
    #[must_use]
    pub fn acr(mut self, acr: String) -> Self {
        self.claims.acr = Some(acr);
        self
    }

    /// Override authentication time (useful for tests)
    #[must_use]
    pub fn auth_time(mut self, auth_time: i64) -> Self {
        self.claims.auth_time = Some(auth_time);
        self
    }

    /// Set authentication methods
    #[must_use]
    pub fn amr(mut self, amr: Vec<String>) -> Self {
        self.claims.amr = Some(amr);
        self
    }

    /// Set session ID
    #[must_use]
    pub fn session_id(mut self, sid: String) -> Self {
        self.claims.sid = Some(sid);
        self
    }

    /// Set access token hash
    ///
    /// # Errors
    ///
    /// Returns an error when the requested JOSE hash algorithm is unsupported
    /// or the hash computation fails closed.
    pub fn access_token_hash(mut self, access_token: &str, alg: &str) -> Result<Self> {
        self.claims.at_hash = Some(compute_hash(access_token, alg)?);
        Ok(self)
    }

    /// Set code hash
    ///
    /// # Errors
    ///
    /// Returns an error when the requested JOSE hash algorithm is unsupported
    /// or the hash computation fails closed.
    pub fn code_hash(mut self, code: &str, alg: &str) -> Result<Self> {
        self.claims.c_hash = Some(compute_hash(code, alg)?);
        Ok(self)
    }

    /// Set signing algorithm
    #[must_use]
    pub fn signing_algorithm(mut self, alg: String) -> Self {
        self.signing_alg = alg;
        self
    }

    /// Add additional claim
    #[must_use]
    pub fn claim(mut self, key: String, value: serde_json::Value) -> Self {
        self.claims.additional_claims.insert(key, value);
        self
    }

    /// Build the ID token
    #[must_use]
    pub fn build(self) -> IdToken {
        IdToken {
            claims: self.claims,
            signing_alg: self.signing_alg,
        }
    }
}

#[cfg(test)]
mod tests;
