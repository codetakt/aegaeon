use super::{TokenPolicyContext, TokenPolicyError, TokenValidator};
use crate::authcode::types::{AccessToken, BearerTokenMeta, SenderBinding};
use crate::metrics_integration::MetricsIntegration;
use crate::policy::SenderConstraint;
use crate::util::jwk_thumbprint_matches;
use std::collections::HashSet;

impl TokenValidator {
    fn enforce_policies(
        &self,
        meta: &BearerTokenMeta,
        context: &TokenPolicyContext<'_>,
    ) -> Result<(), TokenPolicyError> {
        if self.policy.require_scope_subset() && !context.requested_scopes.is_empty() {
            let granted: HashSet<&str> = meta.granted_scopes.iter().map(String::as_str).collect();
            if let Some(missing) = context
                .requested_scopes
                .iter()
                .find(|scope| !granted.contains(**scope))
            {
                return Err(TokenPolicyError::insufficient_scope(*missing));
            }
        }

        if self.policy.require_audience_match() {
            let required = context
                .resource_audience
                .ok_or(TokenPolicyError::ResourceAudienceRequired)?;
            if meta.audience != required {
                return Err(TokenPolicyError::InvalidAudience);
            }
        }

        if self.policy.enforce_sender_binding() {
            match self.policy.sender_constrained {
                SenderConstraint::DPoP => match (&meta.sender_binding, context.sender_dpop_jkt) {
                    (Some(SenderBinding::DPoP { jkt }), Some(present))
                        if jwk_thumbprint_matches(jkt, present) => {}
                    (Some(SenderBinding::DPoP { .. }), Some(_))
                    | (Some(SenderBinding::Mtls { .. }), _) => {
                        return Err(Self::sender_binding_mismatch());
                    }
                    (Some(SenderBinding::DPoP { .. }), None) | (None, _) => {
                        return Err(Self::sender_binding_missing());
                    }
                },
                SenderConstraint::Mtls => {
                    match (&meta.sender_binding, context.sender_mtls_fingerprint) {
                        (Some(SenderBinding::Mtls { fingerprint }), Some(present))
                            if fingerprint == present => {}
                        (Some(SenderBinding::Mtls { .. }), Some(_))
                        | (Some(SenderBinding::DPoP { .. }), _) => {
                            return Err(Self::sender_binding_mismatch());
                        }
                        (Some(SenderBinding::Mtls { .. }), None) | (None, _) => {
                            return Err(Self::sender_binding_missing());
                        }
                    }
                }
                SenderConstraint::None => match (
                    &meta.sender_binding,
                    context.sender_dpop_jkt,
                    context.sender_mtls_fingerprint,
                ) {
                    (Some(SenderBinding::DPoP { jkt }), Some(present), _)
                        if jwk_thumbprint_matches(jkt, present) => {}
                    (Some(SenderBinding::Mtls { fingerprint }), _, Some(present))
                        if fingerprint == present => {}
                    (Some(SenderBinding::DPoP { .. }), Some(_), _)
                    | (Some(SenderBinding::Mtls { .. }), _, Some(_)) => {
                        return Err(Self::sender_binding_mismatch());
                    }
                    (None, _, _) => {}
                    (Some(SenderBinding::DPoP { .. }), None, _)
                    | (Some(SenderBinding::Mtls { .. }), _, None) => {
                        return Err(Self::sender_binding_missing());
                    }
                },
            }
        }

        Ok(())
    }

    /// Validate bearer token and enforce `SecurityPolicy` toggles against request context.
    ///
    /// # Errors
    ///
    /// Returns an error when bearer token validation fails or the request violates the configured
    /// scope, audience, or sender-binding policy.
    pub fn validate_with_policy(
        &self,
        auth_header: &str,
        context: TokenPolicyContext<'_>,
    ) -> Result<(AccessToken, BearerTokenMeta), TokenPolicyError> {
        let (access_token, meta_opt) = self
            .validate_bearer_token_with_meta(auth_header)
            .map_err(TokenPolicyError::from)?;
        let meta = meta_opt.ok_or(TokenPolicyError::BearerMetadataUnavailable)?;
        self.enforce_policies(&meta, &context)?;

        match &meta.refresh_parent {
            Some(parent) if self.policy.retain_refresh_chain() => {
                if self
                    .token_store
                    .try_is_refresh_revoked(parent)
                    .map_err(TokenPolicyError::token_store_unavailable)?
                {
                    return Err(Self::refresh_parent_revoked());
                }
            }
            _ => {}
        }

        Ok((access_token, meta))
    }

    /// Validate bearer token and enforce `SecurityPolicy` toggles against request context,
    /// using the blocking worker pool for token-store I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when bearer token validation fails or the request violates the configured
    /// scope, audience, or sender-binding policy.
    pub async fn validate_with_policy_async(
        &self,
        auth_header: String,
        context: TokenPolicyContext<'_>,
    ) -> Result<(AccessToken, BearerTokenMeta), TokenPolicyError> {
        let (access_token, meta_opt) = self
            .validate_bearer_token_with_meta_async(auth_header)
            .await
            .map_err(TokenPolicyError::from)?;
        let meta = meta_opt.ok_or(TokenPolicyError::BearerMetadataUnavailable)?;
        self.enforce_policies(&meta, &context)?;

        match &meta.refresh_parent {
            Some(parent) if self.policy.retain_refresh_chain() => {
                if self
                    .token_store
                    .try_is_refresh_revoked_async(parent.clone())
                    .await
                    .map_err(TokenPolicyError::token_store_unavailable)?
                {
                    return Err(Self::refresh_parent_revoked());
                }
            }
            _ => {}
        }

        Ok((access_token, meta))
    }

    /// Enforce the configured `SecurityPolicy` for an already validated token metadata object.
    ///
    /// # Errors
    ///
    /// Returns an error when the provided metadata violates the configured scope, audience,
    /// sender-binding, or refresh-chain policy.
    pub fn enforce_with_meta(
        &self,
        meta: &BearerTokenMeta,
        context: TokenPolicyContext<'_>,
    ) -> Result<(), TokenPolicyError> {
        self.enforce_policies(meta, &context)?;

        if self.policy.retain_refresh_chain() {
            if let Some(parent) = &meta.refresh_parent {
                if self
                    .token_store
                    .try_is_refresh_revoked(parent)
                    .map_err(TokenPolicyError::token_store_unavailable)?
                {
                    return Err(Self::refresh_parent_revoked());
                }
            }
        }

        Ok(())
    }

    /// Enforce the configured `SecurityPolicy` for an already validated token metadata object,
    /// using the blocking worker pool for refresh-chain lookups.
    ///
    /// # Errors
    ///
    /// Returns an error when the provided metadata violates the configured scope, audience,
    /// sender-binding, or refresh-chain policy.
    pub async fn enforce_with_meta_async(
        &self,
        meta: &BearerTokenMeta,
        context: TokenPolicyContext<'_>,
    ) -> Result<(), TokenPolicyError> {
        self.enforce_policies(meta, &context)?;

        if self.policy.retain_refresh_chain() {
            if let Some(parent) = &meta.refresh_parent {
                if self
                    .token_store
                    .try_is_refresh_revoked_async(parent.clone())
                    .await
                    .map_err(TokenPolicyError::token_store_unavailable)?
                {
                    return Err(Self::refresh_parent_revoked());
                }
            }
        }

        Ok(())
    }

    fn sender_binding_missing() -> TokenPolicyError {
        Self::emit_sender_binding_failure("sender_binding_missing");
        TokenPolicyError::sender_binding_missing()
    }

    fn sender_binding_mismatch() -> TokenPolicyError {
        Self::emit_sender_binding_failure("sender_binding_mismatch");
        TokenPolicyError::sender_binding_mismatch()
    }

    fn refresh_parent_revoked() -> TokenPolicyError {
        Self::emit_refresh_policy_violation("refresh_parent_revoked");
        TokenPolicyError::RefreshParentRevoked
    }

    fn emit_sender_binding_failure(reason: &str) {
        MetricsIntegration::with_global(|metrics| {
            metrics.record_sender_binding_failure(reason);
        });
    }

    fn emit_refresh_policy_violation(reason: &str) {
        MetricsIntegration::with_global(|metrics| {
            metrics.record_refresh_policy_violation(reason);
        });
    }
}
