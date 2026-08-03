use axum::{response::IntoResponse, Json};
use sqlx::PgPool;
#[cfg(test)]
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::authcode::types::BearerTokenMeta;
use crate::authcode::{
    BearerTokenValidationError, TokenPolicyContext, TokenPolicyError, TokenValidator,
};
use crate::end_user_profiles;
use crate::middleware::tls::normalize_forwarded_client_cert;
use crate::middleware::DpopBinding;
use crate::upstream::{
    filter_downstream_custom_claims, DownstreamClaimSurface, UpstreamClaimReleasePolicy,
};

mod claims;
mod error;
#[cfg(test)]
mod handler;
#[cfg(test)]
mod provider;

pub use self::claims::{filter_claims_by_scope, Address, Userinfo};
pub use self::error::{Error, Result};
#[cfg(test)]
pub use self::handler::userinfo_handler;
#[cfg(test)]
pub use self::provider::{InMemoryUserProvider, SubjectOnlyUserProvider, UserProvider};

#[cfg(test)]
const TEST_USERINFO_ISSUER: &str = "https://auth.example.com";

/// Userinfo endpoint handler
pub struct UserinfoEndpoint {
    validator: TokenValidator,
    source: UserinfoSource,
}

enum UserinfoSource {
    Database {
        db_pool: PgPool,
        issuer: String,
    },
    #[cfg(test)]
    UserProvider(Arc<dyn UserProvider>),
}

impl UserinfoEndpoint {
    #[must_use]
    pub fn new(validator: TokenValidator, db_pool: PgPool, issuer: String) -> Self {
        Self {
            validator,
            source: UserinfoSource::Database { db_pool, issuer },
        }
    }

    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn with_user_provider_for_tests(
        validator: TokenValidator,
        user_provider: Arc<dyn UserProvider>,
    ) -> Self {
        Self {
            validator,
            source: UserinfoSource::UserProvider(user_provider),
        }
    }

    async fn load_user_info(
        &self,
        sub: &str,
        scopes: &[String],
        claim_release_policy: Option<&UpstreamClaimReleasePolicy>,
    ) -> Result<Userinfo> {
        match &self.source {
            UserinfoSource::Database { db_pool, issuer } => {
                let profile =
                    end_user_profiles::load_user_profile_for_subject(db_pool, issuer, sub)
                        .await
                        .map_err(|err| {
                            Error::ServerError(format!("Failed to query local profile: {err}"))
                        })?;
                let claims = profile.as_ref().map_or_else(
                    end_user_profiles::OidcProfileClaims::default,
                    end_user_profiles::oidc_profile_claims_from_record,
                );
                let mut userinfo = filter_claims_by_scope(
                    Userinfo {
                        sub: sub.to_string(),
                        name: claims.display_name,
                        email: claims.email,
                        email_verified: claims.email_verified,
                        updated_at: claims.updated_at_epoch_seconds,
                        custom_claims: claims.custom_claims,
                        ..Default::default()
                    },
                    scopes,
                );
                userinfo.custom_claims = filter_downstream_custom_claims(
                    &userinfo.custom_claims,
                    claim_release_policy,
                    DownstreamClaimSurface::Userinfo,
                );
                Ok(userinfo)
            }
            #[cfg(test)]
            UserinfoSource::UserProvider(provider) => {
                let mut userinfo = provider.get_user_info(sub, scopes)?;
                userinfo.custom_claims = filter_downstream_custom_claims(
                    &userinfo.custom_claims,
                    claim_release_policy,
                    DownstreamClaimSurface::Userinfo,
                );
                Ok(userinfo)
            }
        }
    }

    fn normalize_authorization_header(auth_header: &str) -> Result<String> {
        let mut header_parts = auth_header.split_whitespace();
        let scheme = header_parts.next().unwrap_or("");
        let token_part = header_parts.next().unwrap_or("");
        if token_part.is_empty() || header_parts.next().is_some() {
            return Err(Error::InvalidRequest("Invalid authorization header".into()));
        }
        match scheme.to_ascii_lowercase().as_str() {
            "bearer" | "dpop" => Ok(format!("Bearer {token_part}")),
            _ => Err(Error::InvalidRequest(
                "Authorization scheme must be Bearer or DPoP".into(),
            )),
        }
    }

    async fn validate_bearer_metadata(&self, normalized_auth: String) -> Result<BearerTokenMeta> {
        let (_, meta_opt) = self
            .validator
            .validate_bearer_token_with_meta_async(normalized_auth)
            .await
            .map_err(|err| {
                if matches!(err, BearerTokenValidationError::Internal(_)) {
                    error!(target: "userinfo", "token validation failed internally: {}", err);
                    Error::ServerError("access token validation failed".into())
                } else {
                    warn!(target: "userinfo", "token validation failed: {}", err);
                    Error::InvalidToken
                }
            })?;
        meta_opt.ok_or(Error::InvalidToken)
    }

    fn userinfo_policy_error(err: &TokenPolicyError) -> Error {
        match err {
            TokenPolicyError::Validation(BearerTokenValidationError::Internal(_)) => {
                error!(target: "userinfo", "token validation failed internally: {}", err);
                Error::ServerError("access token validation failed".into())
            }
            TokenPolicyError::Validation(BearerTokenValidationError::Invalid(_)) => {
                warn!(target: "userinfo", "token validation failed: {}", err);
                Error::InvalidToken
            }
            TokenPolicyError::InsufficientScope { .. } => Error::InsufficientScope,
            TokenPolicyError::TokenStoreUnavailable(_) => {
                error!(target: "userinfo", "token store unavailable: {}", err);
                Error::ServerError("token store unavailable".into())
            }
            TokenPolicyError::InvalidAudience
            | TokenPolicyError::SenderBindingMissing
            | TokenPolicyError::SenderBindingMismatch
            | TokenPolicyError::RefreshParentRevoked
            | TokenPolicyError::BearerMetadataUnavailable
            | TokenPolicyError::ResourceAudienceRequired => {
                warn!(target: "userinfo", "policy enforcement failed: {}", err);
                Error::InvalidToken
            }
        }
    }

    async fn enforce_userinfo_policy(
        &self,
        normalized_auth: &str,
        meta_preview: BearerTokenMeta,
        dpop_binding: Option<&DpopBinding>,
        mtls_fingerprint: Option<&str>,
    ) -> Result<BearerTokenMeta> {
        let requested = ["openid"];
        let audience_binding = self.userinfo_audience(&meta_preview);
        let dpop_jkt = dpop_binding.map(|binding| binding.jkt.as_str());
        let normalized_mtls = mtls_fingerprint.and_then(normalize_forwarded_client_cert);
        let normalized_mtls_ref = normalized_mtls.as_deref();
        let context = TokenPolicyContext {
            requested_scopes: &requested,
            resource_audience: Some(audience_binding.as_str()),
            sender_dpop_jkt: dpop_jkt,
            sender_mtls_fingerprint: normalized_mtls_ref,
        };

        if meta_preview.refresh_parent.is_some() {
            return self
                .validator
                .validate_with_policy_async(normalized_auth.to_string(), context)
                .await
                .map(|(_, meta)| meta)
                .map_err(|err| Self::userinfo_policy_error(&err));
        }

        self.validator
            .enforce_with_meta_async(&meta_preview, context)
            .await
            .map_err(|err| Self::userinfo_policy_error(&err))?;
        Ok(meta_preview)
    }

    fn userinfo_audience(&self, _meta: &BearerTokenMeta) -> String {
        match &self.source {
            UserinfoSource::Database { issuer, .. } => crate::resource_audience::userinfo(issuer),
            #[cfg(test)]
            UserinfoSource::UserProvider(_) => {
                crate::resource_audience::userinfo(TEST_USERINFO_ISSUER)
            }
        }
    }

    async fn load_filtered_userinfo(&self, meta: &BearerTokenMeta) -> Result<Userinfo> {
        let userinfo = self
            .load_user_info(
                &meta.user_id,
                &meta.granted_scopes,
                meta.claim_release_policy.as_ref(),
            )
            .await
            .map_err(|e| {
                error!("Failed to get user info: {}", e);
                Error::ServerError("Failed to retrieve user information".into())
            })?;
        info!("Userinfo retrieved for subject: {}", meta.user_id);
        Ok(userinfo)
    }

    /// Fetch userinfo claims after enforcing policy
    ///
    /// # Errors
    ///
    /// Returns an error when the authorization header is invalid, the access
    /// token fails validation/policy checks, or user claims cannot be loaded.
    pub async fn fetch_userinfo(
        &self,
        auth_header: &str,
        dpop_binding: Option<&DpopBinding>,
        mtls_fingerprint: Option<&str>,
    ) -> Result<Userinfo> {
        let normalized_auth = Self::normalize_authorization_header(auth_header)?;
        let meta_preview = self
            .validate_bearer_metadata(normalized_auth.clone())
            .await?;
        let meta = self
            .enforce_userinfo_policy(
                &normalized_auth,
                meta_preview,
                dpop_binding,
                mtls_fingerprint,
            )
            .await?;
        self.load_filtered_userinfo(&meta).await
    }

    /// Handle userinfo request
    ///
    /// # Errors
    ///
    /// Returns an error when [`Self::fetch_userinfo`] rejects the request.
    pub async fn handle(
        &self,
        auth_header: &str,
        dpop_binding: Option<&DpopBinding>,
        mtls_fingerprint: Option<&str>,
    ) -> Result<impl IntoResponse> {
        self.fetch_userinfo(auth_header, dpop_binding, mtls_fingerprint)
            .await
            .map(Json)
    }
}

#[cfg(test)]
mod tests;
