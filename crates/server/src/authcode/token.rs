//! Token issuer and validator with KMS support

mod authorization_code;
mod authorization_code_grant;
mod id_token;
mod jwt_access;
mod refresh_grant;
mod runtime;
mod subject_grants;
mod validator;

pub use self::authorization_code::{AuthorizationCodeIssueError, AuthorizationCodeIssueInput};
use self::id_token::IdTokenBuildInput;
use self::jwt_access::sign_jwt;
pub use self::validator::{
    BearerTokenValidationError, TokenPolicyContext, TokenPolicyError, TokenValidator,
};
use super::store::{AuthCodeStore, TokenStore};
#[cfg(test)]
use super::types::TokenResponse;
use super::types::{AccessToken, CnfClaim};
use crate::kms::KeyManager;
use crate::oidc::{OidcConfig, OidcSessionStore};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ACCESS_TOKEN_TYP: &str = "at+jwt";

/// Input claims and timing for minting a bearer access token.
#[derive(Clone, Copy)]
pub struct BearerAccessTokenMint<'a> {
    pub client_id: &'a str,
    pub subject: &'a str,
    pub scope: Option<&'a str>,
    pub audience: &'a str,
    pub issued_at: SystemTime,
    pub expires_in: u64,
    pub auth_time_epoch_secs: Option<i64>,
    pub acr: Option<&'a str>,
    pub cnf: Option<&'a CnfClaim>,
}

fn generate_jti() -> String {
    aegaeon_crypto::rand::random_base64url(32)
}

fn generate_access_token_value() -> String {
    aegaeon_crypto::rand::random_base64url(32)
}

fn try_unix_epoch_now_secs() -> Result<u64, String> {
    crate::util::now_unix_epoch_secs().map_err(|err| {
        tracing::error!(error = %err, "authcode token clock is before Unix epoch");
        "server_clock_unavailable".to_string()
    })
}

#[cfg(test)]
fn unix_epoch_now_secs() -> u64 {
    match try_unix_epoch_now_secs() {
        Ok(now) => now,
        Err(err) => std::panic::panic_any(format!(
            "test system clock should be after Unix epoch: {err}"
        )),
    }
}

fn access_token_expires_at(now: SystemTime, expires_in: u64) -> Result<SystemTime, ()> {
    now.checked_add(Duration::from_secs(expires_in)).ok_or(())
}

fn access_token_introspection_exp(access_token: &AccessToken) -> Option<u64> {
    let created_at_epoch_secs = access_token
        .created_at
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    created_at_epoch_secs.checked_add(access_token.expires_in)
}

fn split_scopes(scope: Option<&str>) -> Vec<String> {
    crate::oauth_scope::parse_optional_scope_string(scope).unwrap_or_else(|error| {
        tracing::error!(error = %error, "stored token scope failed strict parsing");
        Vec::new()
    })
}

fn trim_non_empty(value: Option<&str>) -> Option<&str> {
    value
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
}

fn validate_optional_resource_indicator(resource: Option<&str>) -> Result<Option<String>, String> {
    trim_non_empty(resource)
        .map(crate::util::validate_resource_indicator)
        .transpose()
}

fn unix_epoch_secs_i64(time: SystemTime) -> Result<i64, ()> {
    let seconds = crate::util::unix_epoch_secs(time).map_err(|_| ())?;
    i64::try_from(seconds).map_err(|_| ())
}

/// Token issuer responsible for minting tokens
pub struct TokenIssuer {
    pub(crate) code_store: AuthCodeStore,
    pub token_store: TokenStore,
    // In production, this would interface with AWS KMS or similar
    key_manager: Arc<dyn KeyManager>,
    oidc: Option<OidcConfig>,
    oidc_sessions: Option<OidcSessionStore>,
    issuer: Option<String>,
    jwt_access_tokens_enabled: bool,
    access_token_ttl_secs: u64,
    refresh_token_ttl_secs: u64,
    authorization_code_ttl_secs: u64,
}

impl TokenIssuer {
    fn access_token_audience(
        &self,
        client_id: &str,
        scope: Option<&str>,
        selected_resource: Option<&str>,
    ) -> String {
        selected_resource.map_or_else(
            || {
                self.oidc
                    .as_ref()
                    .filter(|_| scope_contains(scope, "openid"))
                    .map_or_else(
                        || client_id.to_string(),
                        |cfg| crate::resource_audience::userinfo(&cfg.issuer),
                    )
            },
            str::to_string,
        )
    }

    fn issue_access_token_value(&self, mint: BearerAccessTokenMint<'_>) -> Result<String, String> {
        if mint.expires_in == 0 {
            return Err("expires_in must be positive".to_string());
        }
        if self.jwt_access_tokens_enabled {
            let issuer = self
                .issuer
                .as_deref()
                .ok_or_else(|| "issuer must be configured for JWT access tokens".to_string())?;
            if self.key_manager.jwt_signing_public_jwk().is_none() {
                return Err(
                    "JWT access token signing requires public verification material".to_string(),
                );
            }
            let now_secs = crate::util::unix_epoch_secs(mint.issued_at)
                .map_err(|_| "invalid system clock".to_string())?;
            let exp = now_secs.checked_add(mint.expires_in).ok_or_else(|| {
                "access token expiration is outside representable time".to_string()
            })?;
            let mut claims = serde_json::Map::new();
            claims.insert("iss".to_string(), json!(issuer));
            claims.insert("sub".to_string(), json!(mint.subject));
            claims.insert("aud".to_string(), json!(mint.audience));
            claims.insert("client_id".to_string(), json!(mint.client_id));
            claims.insert("iat".to_string(), json!(now_secs));
            claims.insert("exp".to_string(), json!(exp));
            claims.insert("jti".to_string(), json!(generate_jti()));
            if let Some(scope) = mint.scope.filter(|value| !value.trim().is_empty()) {
                claims.insert("scope".to_string(), json!(scope));
            }
            if let Some(auth_time) = mint.auth_time_epoch_secs {
                claims.insert("auth_time".to_string(), json!(auth_time));
            }
            if let Some(acr_value) = mint.acr.filter(|value| !value.trim().is_empty()) {
                claims.insert("acr".to_string(), json!(acr_value));
            }
            // RFC 9068 §3.1: sender-constrained tokens MUST include a `cnf` claim.
            // DPoP → cnf.jkt, mTLS → cnf.x5t#S256 (per RFC 8705 §3.1).
            match mint.cnf {
                Some(CnfClaim::Jkt(jkt)) if !jkt.trim().is_empty() => {
                    claims.insert("cnf".to_string(), json!({"jkt": jkt}));
                }
                Some(CnfClaim::X5tS256(fp)) if !fp.trim().is_empty() => {
                    claims.insert("cnf".to_string(), json!({"x5t#S256": fp}));
                }
                _ => {}
            }
            let payload = Value::Object(claims);
            sign_jwt(&payload, self.key_manager.as_ref(), ACCESS_TOKEN_TYP)
                .map_err(|e| format!("failed to sign access_token: {e}"))
        } else {
            Ok(generate_access_token_value())
        }
    }

    /// Clean up expired authorization codes, states, nonces, and tokens.
    ///
    /// This should be called periodically (e.g., every 60 seconds) to prevent
    /// unbounded memory growth from expired entries.
    #[cfg(test)]
    pub fn cleanup_expired(&self) {
        self.try_cleanup_expired()
            .expect("test token issuer cleanup should succeed");
    }

    /// Clean up expired authorization codes, states, nonces, and tokens, reporting backend failures.
    pub fn try_cleanup_expired(&self) -> Result<(), String> {
        self.code_store.try_cleanup_expired()?;
        self.token_store.try_cleanup_expired()
    }

    /// Get the current count of tracked states (for monitoring/debugging).
    #[must_use]
    #[cfg(test)]
    pub fn state_count(&self) -> usize {
        self.try_state_count()
            .expect("test token issuer state count should succeed")
    }

    /// Get the current count of tracked states (for monitoring/debugging), reporting backend failures.
    pub fn try_state_count(&self) -> Result<usize, String> {
        self.code_store.try_state_count()
    }

    /// Get the current count of tracked nonces (for monitoring/debugging).
    #[must_use]
    #[cfg(test)]
    pub fn nonce_count(&self) -> usize {
        self.try_nonce_count()
            .expect("test token issuer nonce count should succeed")
    }

    /// Get the current count of tracked nonces (for monitoring/debugging), reporting backend failures.
    pub fn try_nonce_count(&self) -> Result<usize, String> {
        self.code_store.try_nonce_count()
    }

    /// Mint a bearer access token for pre-validated claims and sender constraints.
    ///
    /// # Errors
    ///
    /// Returns an error when the signer cannot issue the access token or the issuer is
    /// misconfigured for JWT access tokens.
    pub fn mint_bearer_access_token(
        &self,
        mint: BearerAccessTokenMint<'_>,
    ) -> Result<String, String> {
        self.issue_access_token_value(BearerAccessTokenMint {
            auth_time_epoch_secs: None,
            acr: None,
            ..mint
        })
    }

    /// Revoke token, reporting backend failures.
    pub fn try_revoke_token(
        &self,
        token: &str,
        _token_type_hint: Option<&str>,
    ) -> Result<(), String> {
        self.token_store.try_revoke_token(token)
    }

    /// Revoke token.
    #[cfg(test)]
    pub fn revoke_token(&self, token: &str, _token_type_hint: Option<&str>) {
        self.try_revoke_token(token, _token_type_hint)
            .expect("test token revocation should succeed");
    }
}

fn is_code_verifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

// Verify PKCE challenge.
// RFC 7636 §4.1: code_verifier MUST be 43..=128 chars from the unreserved ASCII set.
fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    if verifier.len() < 43 || verifier.len() > 128 || !verifier.bytes().all(is_code_verifier_byte) {
        return false;
    }

    let digest = aegaeon_crypto::hash::sha256_digest(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);

    crate::util::constant_time_eq(computed.as_bytes(), challenge.as_bytes())
}

/// Expose the production PKCE binding predicate for spec-oracle differential tests.
#[doc(hidden)]
#[must_use]
pub fn validate_pkce_binding_for_spec_oracle(
    method: &str,
    verifier: &str,
    challenge: &str,
) -> bool {
    method == "S256" && verify_pkce(verifier, challenge)
}

fn scope_contains(scope: Option<&str>, needle: &str) -> bool {
    crate::oauth_scope::parse_optional_scope_string(scope)
        .map(|scopes| scopes.iter().any(|scope| scope == needle))
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "stored token scope failed strict membership parsing");
            false
        })
}

#[cfg(test)]
mod tests;
