use super::issuance;
use crate::authcode::types::{AccessToken, AuthorizationCode, RefreshToken};
use crate::end_user_profiles::OidcProfileClaims;
use crate::upstream::UpstreamClaimReleasePolicy;
use serde_json::Value;
use std::time::SystemTime;

pub(super) struct ValidatedAuthorizationCodeGrant {
    pub(super) code_str: String,
    pub(super) code: AuthorizationCode,
    pub(super) selected_resource: Option<String>,
    pub(super) openid_requested: bool,
}

pub(super) struct PreparedAuthorizationCodeGrantIssue {
    pub(super) code_str: String,
    pub(super) authorization_code_commit_payload: String,
    pub(super) client_id: String,
    pub(super) user_id: String,
    pub(super) scope: Option<String>,
    pub(super) selected_resource: Option<String>,
    pub(super) authorization_details: Option<Value>,
    pub(super) auth_time_epoch_secs: i64,
    pub(super) acr: Option<String>,
    pub(super) auth_session_id: Option<String>,
    pub(super) local_profile: Option<OidcProfileClaims>,
    pub(super) claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    pub(super) nonce: Option<String>,
    pub(super) openid_requested: bool,
    pub(super) access_token: AccessToken,
    pub(super) access_token_str: String,
    pub(super) audience: String,
    pub(super) now: SystemTime,
    pub(super) expires_at: SystemTime,
    pub(super) refresh_token_record: Option<RefreshToken>,
    pub(super) refresh_token: Option<String>,
}

pub(super) struct AuthorizationCodeGrantFinalizationContext {
    pub(super) code_str: String,
    pub(super) client_id: String,
    pub(super) user_id: String,
    pub(super) scope: Option<String>,
    pub(super) selected_resource: Option<String>,
    pub(super) authorization_details: Option<Value>,
    pub(super) auth_time_epoch_secs: i64,
    pub(super) acr: Option<String>,
    pub(super) auth_session_id: Option<String>,
    pub(super) local_profile: Option<OidcProfileClaims>,
    pub(super) claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    pub(super) nonce: Option<String>,
    pub(super) openid_requested: bool,
}

impl PreparedAuthorizationCodeGrantIssue {
    pub(super) fn issue_context(&self) -> issuance::GrantIssueContext<'_> {
        issuance::GrantIssueContext {
            client_id: &self.client_id,
            user_id: &self.user_id,
            scope: self.scope.as_deref(),
            selected_resource: self.selected_resource.as_deref(),
            authorization_details: self.authorization_details.as_ref(),
            auth_time_epoch_secs: self.auth_time_epoch_secs,
            acr: self.acr.as_deref(),
            auth_session_id: self.auth_session_id.as_deref(),
            local_profile: self.local_profile.as_ref(),
            claim_release_policy: self.claim_release_policy.as_ref(),
            nonce: self.nonce.as_deref(),
        }
    }

    pub(super) fn finalization_context(&self) -> AuthorizationCodeGrantFinalizationContext {
        AuthorizationCodeGrantFinalizationContext {
            code_str: self.code_str.clone(),
            client_id: self.client_id.clone(),
            user_id: self.user_id.clone(),
            scope: self.scope.clone(),
            selected_resource: self.selected_resource.clone(),
            authorization_details: self.authorization_details.clone(),
            auth_time_epoch_secs: self.auth_time_epoch_secs,
            acr: self.acr.clone(),
            auth_session_id: self.auth_session_id.clone(),
            local_profile: self.local_profile.clone(),
            claim_release_policy: self.claim_release_policy.clone(),
            nonce: self.nonce.clone(),
            openid_requested: self.openid_requested,
        }
    }
}

impl AuthorizationCodeGrantFinalizationContext {
    pub(super) fn issue_context(&self) -> issuance::GrantIssueContext<'_> {
        issuance::GrantIssueContext {
            client_id: &self.client_id,
            user_id: &self.user_id,
            scope: self.scope.as_deref(),
            selected_resource: self.selected_resource.as_deref(),
            authorization_details: self.authorization_details.as_ref(),
            auth_time_epoch_secs: self.auth_time_epoch_secs,
            acr: self.acr.as_deref(),
            auth_session_id: self.auth_session_id.as_deref(),
            local_profile: self.local_profile.as_ref(),
            claim_release_policy: self.claim_release_policy.as_ref(),
            nonce: self.nonce.as_deref(),
        }
    }
}
