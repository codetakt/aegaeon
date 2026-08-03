use super::{
    scope_contains, unix_epoch_secs_i64, validate_optional_resource_indicator, TokenIssuer,
};
use crate::authcode::code_store::StoreCodeError;
use crate::authcode::store::AuthorizationCodeOneTimeInputCommit;
use crate::authcode::types::{AuthorizationCode, AuthorizationCodeInput, AuthorizationRequest};
use crate::end_user_profiles::OidcProfileClaims;
use crate::upstream::UpstreamClaimReleasePolicy;
use std::time::SystemTime;
use thiserror::Error;

pub struct AuthorizationCodeIssueInput {
    pub req: AuthorizationRequest,
    pub user_id: String,
    pub pkce_required: bool,
    pub auth_time_epoch_secs: i64,
    pub acr: Option<String>,
    pub auth_session_id: Option<String>,
    pub local_profile: Option<OidcProfileClaims>,
    pub claim_release_policy: Option<UpstreamClaimReleasePolicy>,
}

impl AuthorizationCodeIssueInput {
    #[must_use]
    pub fn new(
        req: AuthorizationRequest,
        user_id: String,
        pkce_required: bool,
        auth_time_epoch_secs: i64,
    ) -> Self {
        Self {
            req,
            user_id,
            pkce_required,
            auth_time_epoch_secs,
            acr: None,
            auth_session_id: None,
            local_profile: None,
            claim_release_policy: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum AuthorizationCodeIssueError {
    #[error("invalid_target: {0}")]
    InvalidTarget(String),

    #[error("auth session context is required when requesting the openid scope")]
    OpenIdAuthSessionRequired,

    #[error("nonce is required when requesting the openid scope")]
    NonceRequired,

    #[error("openid scope is not enabled for this server")]
    OpenIdDisabled,

    #[error("PKCE required")]
    PkceRequired,

    #[error("PKCE required (S256)")]
    PkceS256Required,

    #[error("State already used")]
    StateUsed,

    #[error("Nonce already used")]
    NonceUsed,

    #[error("Authorization code already exists")]
    CodeCollision,

    #[error("Authorization code is already expired")]
    CodeExpired,

    #[error("Pushed authorization request is missing or already consumed")]
    PushedAuthorizationRequestMissing,

    #[error("Request Object jti already used")]
    RequestObjectJtiReplay,

    #[error("authorization code store unavailable: {0}")]
    StoreUnavailable(String),

    #[error("system clock is before the UNIX epoch")]
    ClockBeforeUnixEpoch,
}

impl AuthorizationCodeIssueError {
    fn from_store(error: StoreCodeError) -> Self {
        match error {
            StoreCodeError::StateUsed => Self::StateUsed,
            StoreCodeError::NonceUsed => Self::NonceUsed,
            StoreCodeError::CodeCollision => Self::CodeCollision,
            StoreCodeError::Expired => Self::CodeExpired,
            StoreCodeError::PushedAuthorizationRequestMissing => {
                Self::PushedAuthorizationRequestMissing
            }
            StoreCodeError::RequestObjectJtiReplay => Self::RequestObjectJtiReplay,
            StoreCodeError::Storage(error) => Self::StoreUnavailable(error.to_string()),
        }
    }
}

impl TokenIssuer {
    /// Issue authorization code with an explicit PKCE requirement decision.
    ///
    /// When `pkce_required` is false, PKCE is optional but (if present) must use `S256`.
    ///
    /// # Errors
    ///
    /// Returns an error when the request asks for `openid` while OIDC is disabled, omits a
    /// required nonce, violates PKCE policy, or carries an invalid resource indicator.
    pub fn issue_authorization_code_with_pkce_required(
        &self,
        req: AuthorizationRequest,
        user_id: String,
        pkce_required: bool,
        auth_time_epoch_secs: i64,
        acr: Option<String>,
    ) -> Result<(String, Option<String>), String> {
        self.issue_authorization_code_with_local_profile_typed(AuthorizationCodeIssueInput {
            acr,
            ..AuthorizationCodeIssueInput::new(req, user_id, pkce_required, auth_time_epoch_secs)
        })
        .map_err(|error| error.to_string())
    }

    /// Issue an authorization code while snapshotting optional local OIDC profile state.
    ///
    /// # Errors
    ///
    /// Returns an error when the request asks for `openid` while OIDC is disabled, omits a
    /// required nonce, violates PKCE policy, or carries an invalid resource indicator.
    pub fn issue_authorization_code_with_local_profile(
        &self,
        input: AuthorizationCodeIssueInput,
    ) -> Result<(String, Option<String>), String> {
        self.issue_authorization_code_with_local_profile_typed(input)
            .map_err(|error| error.to_string())
    }

    fn issue_authorization_code_with_local_profile_typed(
        &self,
        input: AuthorizationCodeIssueInput,
    ) -> Result<(String, Option<String>), AuthorizationCodeIssueError> {
        let (code, redirect_uri) = self.prepare_authorization_code_issue(input)?;
        let code_str = self
            .code_store
            .store_code_typed(code)
            .map_err(AuthorizationCodeIssueError::from_store)?;

        Ok((code_str, redirect_uri))
    }

    /// Issue an authorization code while snapshotting optional local OIDC profile state,
    /// storing the code on the blocking worker pool.
    ///
    /// # Errors
    ///
    /// Returns an error when request validation fails or the authorization-code store is
    /// unavailable.
    pub async fn issue_authorization_code_with_local_profile_async(
        &self,
        input: AuthorizationCodeIssueInput,
    ) -> Result<(String, Option<String>), String> {
        self.issue_authorization_code_with_local_profile_typed_async(input)
            .await
            .map_err(|error| error.to_string())
    }

    async fn issue_authorization_code_with_local_profile_typed_async(
        &self,
        input: AuthorizationCodeIssueInput,
    ) -> Result<(String, Option<String>), AuthorizationCodeIssueError> {
        let (code, redirect_uri) = self.prepare_authorization_code_issue(input)?;
        let code_str = self
            .code_store
            .store_code_typed_async(code)
            .await
            .map_err(AuthorizationCodeIssueError::from_store)?;

        Ok((code_str, redirect_uri))
    }

    pub(crate) async fn issue_authorization_code_with_local_profile_and_one_time_inputs_async(
        &self,
        input: AuthorizationCodeIssueInput,
        one_time_inputs: AuthorizationCodeOneTimeInputCommit,
    ) -> Result<(String, Option<String>), AuthorizationCodeIssueError> {
        let (code, redirect_uri) = self.prepare_authorization_code_issue(input)?;
        let code_str = self
            .code_store
            .store_code_with_one_time_inputs_typed_async(code, one_time_inputs)
            .await
            .map_err(AuthorizationCodeIssueError::from_store)?;

        Ok((code_str, redirect_uri))
    }

    fn prepare_authorization_code_issue(
        &self,
        input: AuthorizationCodeIssueInput,
    ) -> Result<(AuthorizationCode, Option<String>), AuthorizationCodeIssueError> {
        let AuthorizationCodeIssueInput {
            req,
            user_id,
            pkce_required,
            auth_time_epoch_secs,
            acr,
            auth_session_id,
            local_profile,
            claim_release_policy,
        } = input;

        let resource = validate_optional_resource_indicator(req.resource.as_deref())
            .map_err(AuthorizationCodeIssueError::InvalidTarget)?;

        let openid_requested = scope_contains(req.scope.as_deref(), "openid");
        if openid_requested {
            match self.oidc.as_ref() {
                Some(cfg) => {
                    if auth_session_id
                        .as_deref()
                        .is_none_or(|value| value.trim().is_empty())
                    {
                        return Err(AuthorizationCodeIssueError::OpenIdAuthSessionRequired);
                    }
                    if cfg.require_nonce
                        && req
                            .nonce
                            .as_ref()
                            .is_none_or(|nonce| nonce.trim().is_empty())
                    {
                        return Err(AuthorizationCodeIssueError::NonceRequired);
                    }
                }
                None => {
                    return Err(AuthorizationCodeIssueError::OpenIdDisabled);
                }
            }
        }

        // RFC 9700: Require PKCE for public clients (policy-controlled by caller).
        let (challenge, method) = match (
            req.code_challenge.clone(),
            req.code_challenge_method.clone(),
        ) {
            (Some(challenge), Some(method)) => {
                if method != "S256" {
                    return Err(AuthorizationCodeIssueError::PkceS256Required);
                }
                (Some(challenge), Some(method))
            }
            (None, None) => {
                if pkce_required {
                    return Err(AuthorizationCodeIssueError::PkceRequired);
                }
                (None, None)
            }
            _ => {
                // Missing one of the PKCE parameters. If code_challenge_method is omitted, PKCE
                // defaults to "plain" per RFC 7636 which we forbid by policy.
                return Err(AuthorizationCodeIssueError::PkceRequired);
            }
        };

        let redirect_uri = req.redirect_uri.clone();
        let code = AuthorizationCode::new_with_ttl(
            AuthorizationCodeInput {
                resource,
                authorization_details: req.authorization_details,
                scope: req.scope,
                state: req.state,
                nonce: req.nonce,
                auth_time_epoch_secs,
                acr,
                auth_session_id,
                local_profile,
                claim_release_policy,
                code_challenge: challenge,
                code_challenge_method: method,
                ..AuthorizationCodeInput::new(req.client_id, user_id, redirect_uri)
            },
            self.authorization_code_ttl_secs,
        );

        let redirect_uri = code.redirect_uri.clone();
        Ok((code, redirect_uri))
    }

    /// Issue authorization code (strict mode): PKCE is always required.
    ///
    /// # Errors
    ///
    /// Returns an error when PKCE enforcement or request validation fails.
    pub fn issue_authorization_code(
        &self,
        req: AuthorizationRequest,
        user_id: String,
    ) -> Result<(String, Option<String>), String> {
        let now_epoch_secs = unix_epoch_secs_i64(SystemTime::now())
            .map_err(|_| AuthorizationCodeIssueError::ClockBeforeUnixEpoch.to_string())?;
        self.issue_authorization_code_with_pkce_required(req, user_id, true, now_epoch_secs, None)
    }
}
