use super::super::{access_token_expires_at, BearerAccessTokenMint, TokenIssuer};
use super::context::{PreparedAuthorizationCodeGrantIssue, ValidatedAuthorizationCodeGrant};
use super::error::TokenGrantError;
use super::issuance;
use crate::authcode::types::{AccessToken, CnfClaim, SenderBinding, TokenResponse};
use std::time::SystemTime;

fn code_access_token_ttl(
    exchange_grant: Option<&crate::policy::token_exchange::ExchangeGrant>,
    now: SystemTime,
    configured_ttl: u64,
) -> Result<u64, TokenGrantError> {
    if let Some(grant) = exchange_grant {
        Ok(grant
            .root()
            .and_then(|root| root.expires_at.duration_since(now).ok())
            .map(|duration| duration.as_secs())
            .filter(|seconds| *seconds > 0)
            .ok_or_else(|| TokenGrantError::server("authorization exchange lineage expired"))?
            .min(configured_ttl))
    } else {
        Ok(configured_ttl)
    }
}

impl TokenIssuer {
    pub(super) fn issue_validated_authorization_code_grant(
        &self,
        grant: ValidatedAuthorizationCodeGrant,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        issue_refresh_tokens: bool,
    ) -> Result<TokenResponse, TokenGrantError> {
        let issue = self.prepare_validated_authorization_code_issue(
            grant,
            cnf,
            sender_binding,
            issue_refresh_tokens,
        )?;
        self.finish_validated_authorization_code_issue(issue, sender_binding)
    }

    pub(super) async fn issue_validated_authorization_code_grant_async(
        &self,
        grant: ValidatedAuthorizationCodeGrant,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        issue_refresh_tokens: bool,
    ) -> Result<TokenResponse, TokenGrantError> {
        let issue = self.prepare_validated_authorization_code_issue(
            grant,
            cnf,
            sender_binding,
            issue_refresh_tokens,
        )?;
        self.finish_validated_authorization_code_issue_async(issue, sender_binding)
            .await
    }

    fn prepare_validated_authorization_code_issue(
        &self,
        grant: ValidatedAuthorizationCodeGrant,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        issue_refresh_tokens: bool,
    ) -> Result<PreparedAuthorizationCodeGrantIssue, TokenGrantError> {
        let ValidatedAuthorizationCodeGrant {
            code_str,
            code,
            selected_resource,
            openid_requested,
        } = grant;
        let (code, authorization_code_commit_payload) = code.into_parts();

        let audience = self.access_token_audience(
            &code.client_id,
            code.scope.as_deref(),
            selected_resource.as_deref(),
        );
        let issue_context = issuance::GrantIssueContext {
            client_id: &code.client_id,
            user_id: &code.user_id,
            scope: code.scope.as_deref(),
            selected_resource: selected_resource.as_deref(),
            authorization_details: code.authorization_details.as_ref(),
            auth_time_epoch_secs: code.auth_time_epoch_secs,
            acr: code.acr.as_deref(),
            auth_session_id: code.auth_session_id.as_deref(),
            local_profile: code.local_profile.as_ref(),
            exchange_grant: code.exchange_grant.as_ref(),
            claim_release_policy: code.claim_release_policy.as_ref(),
            nonce: code.nonce.as_deref(),
        };

        let refresh_token_record = self.refresh_token_for_authorization_code_grant(
            &issue_context,
            &audience,
            issue_refresh_tokens,
            sender_binding,
        );
        let refresh_token = refresh_token_record
            .as_ref()
            .map(|token| token.token.clone());

        // Target authority needs a refresh lineage. Keep the code-time snapshot,
        // but publish it only with the parent that actually receives that snapshot.
        // No-parent access tokens retain only the legacy same-audience capability.
        let exchange_grant = refresh_token_record
            .as_ref()
            .and_then(|refresh| refresh.exchange_grant.clone());

        let now = SystemTime::now();
        let expires_in =
            code_access_token_ttl(exchange_grant.as_ref(), now, self.access_token_ttl_secs)?;
        let expires_at = access_token_expires_at(now, expires_in).map_err(|()| {
            TokenGrantError::server("access token expiry is outside representable time")
        })?;
        let access_token_str = self
            .issue_access_token_value(BearerAccessTokenMint {
                subject: &code.user_id,
                client_id: &code.client_id,
                scope: code.scope.as_deref(),
                audience: &audience,
                issued_at: now,
                expires_in,
                auth_time_epoch_secs: Some(code.auth_time_epoch_secs),
                acr: code.acr.as_deref(),
                cnf,
            })
            .map_err(TokenGrantError::server)?;
        let access_token = AccessToken {
            exchange_root: exchange_grant
                .as_ref()
                .and_then(|grant| grant.root())
                .cloned(),
            token: access_token_str.clone(),
            token_type: AccessToken::type_for_confirmation(cnf).to_string(),
            client_id: code.client_id.clone(),
            user_id: code.user_id.clone(),
            scope: code.scope.clone(),
            expires_in,
            created_at: now,
            cnf: cnf.cloned(),
        };

        Ok(PreparedAuthorizationCodeGrantIssue {
            code_str,
            authorization_code_commit_payload,
            client_id: code.client_id,
            user_id: code.user_id,
            scope: code.scope,
            selected_resource,
            authorization_details: code.authorization_details,
            auth_time_epoch_secs: code.auth_time_epoch_secs,
            acr: code.acr,
            auth_session_id: code.auth_session_id,
            local_profile: code.local_profile,
            exchange_grant,
            claim_release_policy: code.claim_release_policy,
            nonce: code.nonce,
            openid_requested,
            access_token,
            access_token_str,
            audience,
            now,
            expires_at,
            refresh_token_record,
            refresh_token,
        })
    }
}
