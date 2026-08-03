use super::jwt_access::{
    verify_jwt, JwtAccessTokenAudience, JwtAccessTokenHeader, JwtAccessTokenPayload,
    JwtAccessTokenVerificationError,
};
use super::{access_token_introspection_exp, try_unix_epoch_now_secs, ACCESS_TOKEN_TYP};
use crate::authcode::store::TokenStore;
use crate::authcode::types::{AccessToken, BearerTokenMeta};
use crate::kms::KeyManager;
use crate::policy::SecurityPolicy;
use crate::util::{extract_bearer_token, BearerTokenError};
use serde_json::json;
use std::sync::Arc;

mod policy;
mod types;

pub use types::{BearerTokenValidationError, TokenPolicyContext, TokenPolicyError};

#[derive(Clone)]
/// Token validator for resource servers
pub struct TokenValidator {
    token_store: TokenStore,
    key_manager: Arc<dyn KeyManager>,
    policy: SecurityPolicy,
    jwt_access_tokens_enabled: bool,
    jwt_leeway_secs: u64,
    issuer: Option<String>,
}

impl TokenValidator {
    pub fn new(token_store: TokenStore, key_manager: Arc<dyn KeyManager>) -> Self {
        Self::with_policy(token_store, key_manager, SecurityPolicy::default())
    }

    pub fn with_policy(
        token_store: TokenStore,
        key_manager: Arc<dyn KeyManager>,
        policy: SecurityPolicy,
    ) -> Self {
        Self {
            token_store,
            key_manager,
            policy,
            jwt_access_tokens_enabled: false,
            jwt_leeway_secs: 60,
            issuer: None,
        }
    }

    #[must_use]
    pub fn with_jwt_access_tokens_enabled(mut self, enabled: bool) -> Self {
        self.jwt_access_tokens_enabled = enabled;
        self
    }

    #[must_use]
    pub const fn with_jwt_leeway_secs(mut self, leeway_secs: u64) -> Self {
        self.jwt_leeway_secs = leeway_secs;
        self
    }

    #[must_use]
    pub fn with_issuer(mut self, issuer: Option<String>) -> Self {
        self.issuer = issuer;
        self
    }

    /// Validate bearer token and return both token and optional metadata
    ///
    /// # Errors
    ///
    /// Returns an error when the bearer transport is malformed, the token cannot be verified, or
    /// the stored metadata is inconsistent with JWT claims.
    pub fn validate_bearer_token_with_meta(
        &self,
        auth_header: &str,
    ) -> Result<(AccessToken, Option<BearerTokenMeta>), BearerTokenValidationError> {
        let token =
            extract_bearer_token(Some(auth_header), None, None).map_err(|err| match err {
                BearerTokenError::Missing => {
                    BearerTokenValidationError::invalid("Missing bearer token")
                }
                BearerTokenError::InvalidScheme => BearerTokenValidationError::invalid(
                    "Authorization header must use the Bearer scheme",
                ),
                BearerTokenError::MultipleMethods => BearerTokenValidationError::invalid(
                    "Bearer token supplied via multiple transport methods",
                ),
            })?;

        let verified = if self.jwt_access_tokens_enabled {
            let verified = verify_jwt(&token, self.key_manager.as_ref())
                .map_err(|err| match err {
                    JwtAccessTokenVerificationError::KeyManager(err) => {
                        BearerTokenValidationError::internal(format!(
                            "Token verification error: {err}"
                        ))
                    }
                    JwtAccessTokenVerificationError::BackendPolicy(surface) => BearerTokenValidationError::internal(
                        format!(
                            "access token parser backend misconfigured: unsupported raw JSON backend for {surface}"
                        ),
                    ),
                })?
                .ok_or_else(|| BearerTokenValidationError::invalid("Invalid token signature"))?;
            Self::enforce_access_token_typ(&verified.header)
                .map_err(BearerTokenValidationError::invalid)?;
            self.enforce_access_token_claims(&verified.payload, self.issuer.as_deref())
                .map_err(BearerTokenValidationError::invalid)?;
            Some(verified)
        } else {
            None
        };

        let access = self
            .token_store
            .try_verify_access_token(&token)
            .map_err(|err| {
                BearerTokenValidationError::internal(format!(
                    "token store access lookup failed: {err}"
                ))
            })?
            .ok_or_else(|| BearerTokenValidationError::invalid("Invalid or expired token"))?;
        let meta = self
            .token_store
            .try_get_bearer_meta(&token)
            .map_err(|err| {
                BearerTokenValidationError::internal(format!(
                    "token store metadata lookup failed: {err}"
                ))
            })?;
        if let (Some(ref verified), Some(ref meta)) = (&verified, &meta) {
            if !Self::aud_matches(&verified.payload, &meta.audience) {
                return Err(BearerTokenValidationError::invalid(
                    "invalid_token_audience",
                ));
            }
        }
        Ok((access, meta))
    }

    /// Validate bearer token and return both token and optional metadata, using
    /// the blocking worker pool for token-store I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when the bearer transport is malformed, the token cannot be verified, or
    /// the stored metadata is inconsistent with JWT claims.
    pub async fn validate_bearer_token_with_meta_async(
        &self,
        auth_header: String,
    ) -> Result<(AccessToken, Option<BearerTokenMeta>), BearerTokenValidationError> {
        let token = extract_bearer_token(Some(auth_header.as_str()), None, None).map_err(
            |err| match err {
                BearerTokenError::Missing => {
                    BearerTokenValidationError::invalid("Missing bearer token")
                }
                BearerTokenError::InvalidScheme => BearerTokenValidationError::invalid(
                    "Authorization header must use the Bearer scheme",
                ),
                BearerTokenError::MultipleMethods => BearerTokenValidationError::invalid(
                    "Bearer token supplied via multiple transport methods",
                ),
            },
        )?;

        let verified = if self.jwt_access_tokens_enabled {
            let verified = verify_jwt(&token, self.key_manager.as_ref())
                .map_err(|err| match err {
                    JwtAccessTokenVerificationError::KeyManager(err) => {
                        BearerTokenValidationError::internal(format!(
                            "Token verification error: {err}"
                        ))
                    }
                    JwtAccessTokenVerificationError::BackendPolicy(surface) => BearerTokenValidationError::internal(
                        format!(
                            "access token parser backend misconfigured: unsupported raw JSON backend for {surface}"
                        ),
                    ),
                })?
                .ok_or_else(|| BearerTokenValidationError::invalid("Invalid token signature"))?;
            Self::enforce_access_token_typ(&verified.header)
                .map_err(BearerTokenValidationError::invalid)?;
            self.enforce_access_token_claims(&verified.payload, self.issuer.as_deref())
                .map_err(BearerTokenValidationError::invalid)?;
            Some(verified)
        } else {
            None
        };

        let access = self
            .token_store
            .try_verify_access_token_async(token.clone())
            .await
            .map_err(|err| {
                BearerTokenValidationError::internal(format!(
                    "token store access lookup failed: {err}"
                ))
            })?
            .ok_or_else(|| BearerTokenValidationError::invalid("Invalid or expired token"))?;
        let meta = self
            .token_store
            .try_get_bearer_meta_async(token)
            .await
            .map_err(|err| {
                BearerTokenValidationError::internal(format!(
                    "token store metadata lookup failed: {err}"
                ))
            })?;
        if let (Some(ref verified), Some(ref meta)) = (&verified, &meta) {
            if !Self::aud_matches(&verified.payload, &meta.audience) {
                return Err(BearerTokenValidationError::invalid(
                    "invalid_token_audience",
                ));
            }
        }
        Ok((access, meta))
    }

    /// Validate bearer token from Authorization header
    ///
    /// # Errors
    ///
    /// Returns an error when the bearer token is malformed, invalid, or expired.
    pub fn validate_bearer_token(&self, auth_header: &str) -> Result<AccessToken, String> {
        self.validate_bearer_token_with_meta(auth_header)
            .map_err(|err| err.to_string())
            .map(|(token, _)| token)
    }

    fn enforce_access_token_typ(header: &JwtAccessTokenHeader) -> Result<(), String> {
        let typ = header.typ.as_deref();
        match typ {
            Some(ACCESS_TOKEN_TYP | "application/at+jwt") => Ok(()),
            _ => Err("invalid_token_typ".to_string()),
        }
    }

    fn enforce_access_token_claims(
        &self,
        payload: &JwtAccessTokenPayload,
        issuer: Option<&str>,
    ) -> Result<(), String> {
        let iss = payload.iss.as_deref();
        if iss.is_none() {
            return Err("invalid_token_issuer".to_string());
        }
        if let Some(expected) = issuer {
            if iss != Some(expected) {
                return Err("invalid_token_issuer".to_string());
            }
        }
        if payload.sub.is_none() {
            return Err("invalid_token_subject".to_string());
        }
        if !payload.aud_present {
            return Err("invalid_token_audience".to_string());
        }
        if payload.aud.is_none() {
            return Err("invalid_token_audience".to_string());
        }
        if payload.exp.is_none() {
            return Err("invalid_token_exp".to_string());
        }
        if payload.iat.is_none() {
            return Err("invalid_token_iat".to_string());
        }
        self.enforce_access_token_times(payload)?;
        if payload.jti.is_none() {
            return Err("invalid_token_id".to_string());
        }
        Ok(())
    }

    fn enforce_access_token_times(&self, payload: &JwtAccessTokenPayload) -> Result<(), String> {
        let exp = payload.exp.ok_or_else(|| "invalid_token_exp".to_string())?;
        let iat = payload.iat.ok_or_else(|| "invalid_token_iat".to_string())?;
        if exp <= iat {
            return Err("invalid_token_exp".to_string());
        }

        let now = try_unix_epoch_now_secs()?;
        let leeway = self.jwt_leeway_secs;
        let exp_with_leeway = exp
            .checked_add(leeway)
            .ok_or_else(|| "invalid_token_exp".to_string())?;
        if exp_with_leeway < now {
            return Err("invalid_token_exp".to_string());
        }
        let now_with_leeway = now
            .checked_add(leeway)
            .ok_or_else(|| "invalid_token_iat".to_string())?;
        if iat > now_with_leeway {
            return Err("invalid_token_iat".to_string());
        }
        Ok(())
    }

    fn aud_matches(payload: &JwtAccessTokenPayload, expected: &str) -> bool {
        match payload.aud.as_ref() {
            Some(JwtAccessTokenAudience::Single(aud)) => aud == expected,
            Some(JwtAccessTokenAudience::Multiple(list)) => {
                list.iter().any(|value| value == expected)
            }
            None => false,
        }
    }

    /// Introspect token (RFC 7662)
    #[must_use]
    pub fn introspect_token(&self, token: &str) -> serde_json::Value {
        match self.token_store.try_verify_access_token(token) {
            Ok(Some(access_token)) => access_token_introspection_exp(&access_token).map_or_else(
                || json!({ "active": false }),
                |exp| {
                    json!({
                        "active": true,
                        "scope": access_token.scope,
                        "client_id": access_token.client_id,
                        "username": access_token.user_id,
                        "token_type": "Bearer",
                        "exp": exp,
                    })
                },
            ),
            Ok(None) | Err(_) => json!({ "active": false }),
        }
    }
}
