use super::super::TokenIssuer;
use super::context::{
    AuthorizationCodeGrantFinalizationContext, PreparedAuthorizationCodeGrantIssue,
};
use super::error::{TokenGrantError, TokenGrantErrorCode};
use super::issuance;
use crate::authcode::store::{AuthorizationCodeGrantCommit, AUTHORIZATION_CODE_GRANT_CODE_MISSING};
use crate::authcode::types::{SenderBinding, TokenResponse};
use crate::oidc::OidcSessionGrantCommit;

impl TokenIssuer {
    fn prepare_id_token_for_authorization_code_issue(
        &self,
        issue: &AuthorizationCodeGrantFinalizationContext,
        access_token: &str,
    ) -> Result<(Option<String>, Option<OidcSessionGrantCommit>), TokenGrantError> {
        let issue_context = issue.issue_context();
        let session_commit =
            self.prepare_oidc_session_commit_for_grant(issue.openid_requested, &issue_context)?;
        let id_token = self.issue_id_token_for_authorization_code_grant(
            issue.openid_requested,
            &issue_context,
            session_commit.as_ref().map(OidcSessionGrantCommit::sid),
            access_token,
            &issue.code_str,
        )?;
        Ok((id_token, session_commit))
    }

    async fn prepare_id_token_for_authorization_code_issue_async(
        &self,
        issue: &AuthorizationCodeGrantFinalizationContext,
        access_token: &str,
    ) -> Result<(Option<String>, Option<OidcSessionGrantCommit>), TokenGrantError> {
        let issue_context = issue.issue_context();
        let session_commit = self
            .prepare_oidc_session_commit_for_grant_async(issue.openid_requested, &issue_context)
            .await?;
        let id_token = self
            .issue_id_token_for_authorization_code_grant_async(
                issue.openid_requested,
                &issue_context,
                session_commit.as_ref().map(OidcSessionGrantCommit::sid),
                access_token,
                &issue.code_str,
            )
            .await?;
        Ok((id_token, session_commit))
    }

    pub(super) fn finish_validated_authorization_code_issue(
        &self,
        mut issue: PreparedAuthorizationCodeGrantIssue,
        sender_binding: Option<&SenderBinding>,
    ) -> Result<TokenResponse, TokenGrantError> {
        let finalization = issue.finalization_context();
        let (id_token, oidc_session_commit) = self.prepare_id_token_for_authorization_code_issue(
            &finalization,
            &issue.access_token_str,
        )?;
        let meta = {
            let issue_context = issue.issue_context();
            issuance::bearer_meta_for_authorization_code_grant(
                &issue_context,
                issue.access_token_str.clone(),
                issue.audience.clone(),
                sender_binding.cloned(),
                issue.now,
                issue.expires_at,
                issue.refresh_token.clone(),
            )
        };
        let (access_token_str, refresh_token) = self
            .token_store
            .store_issued_authorization_code_grant(AuthorizationCodeGrantCommit::new(
                self.code_store.clone(),
                issue.code_str.clone(),
                issue.authorization_code_commit_payload.clone(),
                issue.access_token,
                issue.refresh_token_record.take(),
                meta,
                oidc_session_commit
                    .as_ref()
                    .and_then(OidcSessionGrantCommit::redis_commit)
                    .cloned(),
            ))
            .map_err(map_authorization_code_grant_commit_error)?;

        Ok(TokenResponse::Success {
            access_token: access_token_str,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_ttl_secs,
            refresh_token,
            scope: issue.scope,
            id_token,
            authorization_details: issue.authorization_details,
        })
    }

    pub(super) async fn finish_validated_authorization_code_issue_async(
        &self,
        mut issue: PreparedAuthorizationCodeGrantIssue,
        sender_binding: Option<&SenderBinding>,
    ) -> Result<TokenResponse, TokenGrantError> {
        let finalization = issue.finalization_context();
        let (id_token, oidc_session_commit) = self
            .prepare_id_token_for_authorization_code_issue_async(
                &finalization,
                &issue.access_token_str,
            )
            .await?;
        let meta = {
            let issue_context = issue.issue_context();
            issuance::bearer_meta_for_authorization_code_grant(
                &issue_context,
                issue.access_token_str.clone(),
                issue.audience.clone(),
                sender_binding.cloned(),
                issue.now,
                issue.expires_at,
                issue.refresh_token.clone(),
            )
        };
        let (access_token_str, refresh_token) = self
            .token_store
            .store_issued_authorization_code_grant_async(AuthorizationCodeGrantCommit::new(
                self.code_store.clone(),
                issue.code_str.clone(),
                issue.authorization_code_commit_payload.clone(),
                issue.access_token,
                issue.refresh_token_record.take(),
                meta,
                oidc_session_commit
                    .as_ref()
                    .and_then(OidcSessionGrantCommit::redis_commit)
                    .cloned(),
            ))
            .await
            .map_err(map_authorization_code_grant_commit_error)?;

        Ok(TokenResponse::Success {
            access_token: access_token_str,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_ttl_secs,
            refresh_token,
            scope: issue.scope,
            id_token,
            authorization_details: issue.authorization_details,
        })
    }
}

fn map_authorization_code_grant_commit_error(error: String) -> TokenGrantError {
    if error == AUTHORIZATION_CODE_GRANT_CODE_MISSING {
        TokenGrantError::described(TokenGrantErrorCode::InvalidGrant, "Invalid or expired code")
    } else {
        TokenGrantError::server(error)
    }
}
