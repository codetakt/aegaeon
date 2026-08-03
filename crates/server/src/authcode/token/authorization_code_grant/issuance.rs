use super::super::{scope_contains, split_scopes, IdTokenBuildInput, TokenIssuer};
use super::error::TokenGrantError;
use crate::authcode::types::{
    BearerTokenMeta, BearerTokenMetaInput, RefreshToken, RefreshTokenInput, SenderBinding,
};
use crate::end_user_profiles::OidcProfileClaims;
use crate::oidc::{OidcSessionContext, OidcSessionGrantCommit};
use crate::upstream::UpstreamClaimReleasePolicy;
use serde_json::Value;
use std::time::SystemTime;

pub(super) struct GrantIssueContext<'a> {
    pub(super) client_id: &'a str,
    pub(super) user_id: &'a str,
    pub(super) scope: Option<&'a str>,
    pub(super) selected_resource: Option<&'a str>,
    pub(super) authorization_details: Option<&'a Value>,
    pub(super) auth_time_epoch_secs: i64,
    pub(super) acr: Option<&'a str>,
    pub(super) auth_session_id: Option<&'a str>,
    pub(super) local_profile: Option<&'a OidcProfileClaims>,
    pub(super) claim_release_policy: Option<&'a UpstreamClaimReleasePolicy>,
    pub(super) nonce: Option<&'a str>,
}

impl TokenIssuer {
    pub(super) fn refresh_token_for_authorization_code_grant(
        &self,
        ctx: &GrantIssueContext<'_>,
        issue_refresh_tokens: bool,
        sender_binding: Option<&SenderBinding>,
    ) -> Option<RefreshToken> {
        if !issue_refresh_tokens || !scope_contains(ctx.scope, "offline_access") {
            return None;
        }

        let mut refresh = RefreshToken::with_ttl(
            RefreshTokenInput {
                scope: ctx.scope.map(str::to_string),
                resource: ctx.selected_resource.map(str::to_string),
                authorization_details: ctx.authorization_details.cloned(),
                auth_time_epoch_secs: ctx.auth_time_epoch_secs,
                acr: ctx.acr.map(str::to_string),
                ..RefreshTokenInput::new(ctx.client_id.to_string(), ctx.user_id.to_string())
            },
            self.refresh_token_ttl_secs,
        );
        refresh.claim_release_policy = ctx.claim_release_policy.cloned();
        refresh.sender_binding = sender_binding.cloned();
        Some(refresh)
    }

    pub(super) fn prepare_oidc_session_commit_for_grant(
        &self,
        openid_requested: bool,
        ctx: &GrantIssueContext<'_>,
    ) -> Result<Option<OidcSessionGrantCommit>, TokenGrantError> {
        if !openid_requested {
            return Ok(None);
        }
        let Some(store) = self.oidc_sessions.as_ref() else {
            return Ok(None);
        };

        let auth_session_id = ctx
            .auth_session_id
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| server_error("OIDC auth session context is missing"))?;
        let commit = store
            .prepare_authorization_code_grant_commit(
                OidcSessionContext {
                    user_id: ctx.user_id,
                    auth_session_id,
                },
                ctx.client_id,
            )
            .map_err(|err| {
                tracing::error!(
                    error = %err,
                    "OIDC session grant commit preparation failed during token issuance"
                );
                server_error("OIDC session allocation failed")
            })?;

        Ok(Some(commit))
    }

    pub(super) async fn prepare_oidc_session_commit_for_grant_async(
        &self,
        openid_requested: bool,
        ctx: &GrantIssueContext<'_>,
    ) -> Result<Option<OidcSessionGrantCommit>, TokenGrantError> {
        if !openid_requested {
            return Ok(None);
        }
        let Some(store) = self.oidc_sessions.as_ref() else {
            return Ok(None);
        };

        let auth_session_id = ctx
            .auth_session_id
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| server_error("OIDC auth session context is missing"))?;
        let commit = store
            .prepare_authorization_code_grant_commit_async(
                OidcSessionContext {
                    user_id: ctx.user_id,
                    auth_session_id,
                },
                ctx.client_id,
            )
            .await
            .map_err(|err| {
                tracing::error!(
                    error = %err,
                    "OIDC session grant commit preparation failed during token issuance"
                );
                server_error("OIDC session allocation failed")
            })?;

        Ok(Some(commit))
    }

    pub(super) fn issue_id_token_for_authorization_code_grant(
        &self,
        openid_requested: bool,
        ctx: &GrantIssueContext<'_>,
        session_id: Option<&str>,
        access_token: &str,
        code: &str,
    ) -> Result<Option<String>, TokenGrantError> {
        if !openid_requested {
            return Ok(None);
        }
        let Some(cfg) = self.oidc.as_ref() else {
            return Ok(None);
        };

        Self::build_id_token(
            cfg,
            IdTokenBuildInput {
                client_id: ctx.client_id,
                user_id: ctx.user_id,
                scope: ctx.scope,
                local_profile: ctx.local_profile,
                claim_release_policy: ctx.claim_release_policy,
                session_id,
                nonce: ctx.nonce,
                auth_time_epoch_secs: ctx.auth_time_epoch_secs,
                acr: ctx.acr,
                access_token,
                code,
            },
        )
        .map(Some)
        .map_err(TokenGrantError::from)
    }

    pub(super) async fn issue_id_token_for_authorization_code_grant_async(
        &self,
        openid_requested: bool,
        ctx: &GrantIssueContext<'_>,
        session_id: Option<&str>,
        access_token: &str,
        code: &str,
    ) -> Result<Option<String>, TokenGrantError> {
        if !openid_requested {
            return Ok(None);
        }
        let Some(cfg) = self.oidc.as_ref() else {
            return Ok(None);
        };

        Self::build_id_token_async(
            cfg,
            IdTokenBuildInput {
                client_id: ctx.client_id,
                user_id: ctx.user_id,
                scope: ctx.scope,
                local_profile: ctx.local_profile,
                claim_release_policy: ctx.claim_release_policy,
                session_id,
                nonce: ctx.nonce,
                auth_time_epoch_secs: ctx.auth_time_epoch_secs,
                acr: ctx.acr,
                access_token,
                code,
            },
        )
        .await
        .map(Some)
        .map_err(TokenGrantError::from)
    }
}

pub(super) fn bearer_meta_for_authorization_code_grant(
    ctx: &GrantIssueContext<'_>,
    token_id: String,
    audience: String,
    sender_binding: Option<SenderBinding>,
    issued_at: SystemTime,
    expires_at: SystemTime,
    refresh_parent: Option<String>,
) -> BearerTokenMeta {
    let mut meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id,
        client_id: ctx.client_id.to_string(),
        user_id: ctx.user_id.to_string(),
        granted_scopes: split_scopes(ctx.scope),
        audience,
        sender_binding,
        authorization_details: ctx.authorization_details.cloned(),
        auth_time_epoch_secs: Some(ctx.auth_time_epoch_secs),
        acr: ctx.acr.map(str::to_string),
        issued_at,
        expires_at,
        refresh_parent,
    });
    meta.claim_release_policy = ctx.claim_release_policy.cloned();
    meta
}

fn server_error(description: impl Into<String>) -> TokenGrantError {
    TokenGrantError::server(description)
}
