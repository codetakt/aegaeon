use super::{access_token_introspection_exp, try_unix_epoch_now_secs};
use crate::authcode::store::TokenStore;
use crate::authcode::types::{AccessToken, BearerTokenMeta};
use crate::kms::{AccessTokenVerifier, KeyManager, KeyManagerAccessTokenVerifier};
use crate::policy::SecurityPolicy;
use crate::util::{extract_bearer_token, BearerTokenError};
use serde_json::json;
use std::sync::Arc;

mod jwt;
mod policy;
mod types;

pub use types::{BearerTokenValidationError, TokenPolicyContext, TokenPolicyError};

#[derive(Clone)]
/// Token validator for resource servers
pub struct TokenValidator {
    token_store: TokenStore,
    access_verifier: Arc<dyn AccessTokenVerifier>,
    now: fn() -> Result<u64, String>,
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
            access_verifier: Arc::new(KeyManagerAccessTokenVerifier(key_manager)),
            now: try_unix_epoch_now_secs,
            policy,
            jwt_access_tokens_enabled: false,
            jwt_leeway_secs: 60,
            issuer: None,
        }
    }

    /// Override the compatibility manager adapter with an explicit access verification capability.
    #[must_use]
    pub fn with_access_token_verifier(mut self, verifier: Arc<dyn AccessTokenVerifier>) -> Self {
        self.access_verifier = verifier;
        self
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

        let verified = self.verify_access_jwt(&token, self.jwt_access_tokens_enabled)?;
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
        if access.client_credentials_digest.is_some()
            || meta
                .as_ref()
                .is_some_and(|meta| meta.client_credentials_grant.is_some())
        {
            let Some(meta) = meta.as_ref() else {
                return Err(BearerTokenValidationError::invalid(
                    "client-credentials authority missing",
                ));
            };
            crate::authcode::store::bearer_metadata_matches_access_token(&access, meta)
                .map_err(BearerTokenValidationError::invalid)?;
        }
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

        let verified = self.verify_access_jwt(&token, self.jwt_access_tokens_enabled)?;
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
        if access.client_credentials_digest.is_some()
            || meta
                .as_ref()
                .is_some_and(|meta| meta.client_credentials_grant.is_some())
        {
            let Some(meta) = meta.as_ref() else {
                return Err(BearerTokenValidationError::invalid(
                    "client-credentials authority missing",
                ));
            };
            crate::authcode::store::bearer_metadata_matches_access_token(&access, meta)
                .map_err(BearerTokenValidationError::invalid)?;
        }
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

    /// Inspect legacy stored-token status without an online authority backend.
    /// Either stored client-credentials marker, and any lookup failure, yields inactive.
    /// Use the HTTP
    /// introspection endpoint for authenticated current-policy evaluation (RFC 7662).
    #[must_use]
    pub fn introspect_token(&self, token: &str) -> serde_json::Value {
        let Ok(Some(access_token)) = self.token_store.try_verify_access_token(token) else {
            return json!({ "active": false });
        };
        if access_token.client_credentials_digest.is_some() {
            return json!({ "active": false });
        }
        let meta = match self.token_store.try_get_bearer_meta(token) {
            Ok(Some(meta)) if meta.client_credentials_grant.is_some() => {
                return json!({ "active": false });
            }
            Err(_) => return json!({ "active": false }),
            Ok(meta) => meta,
        };
        if self
            .validate_stored_access_token_jwt(&access_token, meta.as_ref())
            .is_err()
        {
            return json!({ "active": false });
        }
        access_token_introspection_exp(&access_token).map_or_else(
            || json!({ "active": false }),
            |exp| {
                let mut body = json!({
                    "active": true,
                    "client_id": access_token.client_id,
                    "username": access_token.user_id,
                    "token_type": access_token.token_type,
                    "exp": exp,
                });
                if let Some(scope) = access_token.scope.as_ref() {
                    body["scope"] = json!(scope);
                }
                body
            },
        )
    }
}
