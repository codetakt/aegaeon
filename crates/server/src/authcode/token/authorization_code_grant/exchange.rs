use super::super::TokenIssuer;
use super::error::{TokenExchangeError, TokenExchangeResult};
use super::request::{
    authorization_code_grant_exchange_lock_error, take_authorization_code_request,
};
use crate::authcode::types::{CnfClaim, SenderBinding, TokenRequest, TokenResponse};

#[derive(Clone, Copy)]
pub(super) struct AuthorizationCodeGrantPolicy {
    pub(super) authorization_code_grant_allowed: bool,
    pub(super) issue_refresh_tokens: bool,
}

impl TokenIssuer {
    pub(super) fn exchange_authorization_code_grant(
        &self,
        req: TokenRequest,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        policy: AuthorizationCodeGrantPolicy,
    ) -> Result<TokenResponse, String> {
        self.try_exchange_authorization_code_grant(req, cnf, sender_binding, policy)
            .or_else(TokenExchangeError::into_token_response_result)
    }

    pub(super) async fn exchange_authorization_code_grant_async(
        &self,
        req: TokenRequest,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        policy: AuthorizationCodeGrantPolicy,
    ) -> Result<TokenResponse, String> {
        self.try_exchange_authorization_code_grant_async(req, cnf, sender_binding, policy)
            .await
            .or_else(TokenExchangeError::into_token_response_result)
    }

    pub(super) async fn exchange_authorization_code_grant_for_token_endpoint_async(
        &self,
        req: TokenRequest,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        policy: AuthorizationCodeGrantPolicy,
    ) -> Result<TokenResponse, super::error::AuthorizationCodeTokenExchangeError> {
        self.try_exchange_authorization_code_grant_async(req, cnf, sender_binding, policy)
            .await
            .or_else(TokenExchangeError::into_token_response_or_exchange_error)
    }

    fn try_exchange_authorization_code_grant(
        &self,
        req: TokenRequest,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        policy: AuthorizationCodeGrantPolicy,
    ) -> TokenExchangeResult<TokenResponse> {
        let (req, code_str) = take_authorization_code_request(req)?;
        let guard = self
            .code_store
            .acquire_exchange_lock(&code_str)
            .map_err(authorization_code_grant_exchange_lock_error)?;
        let result = (|| {
            let grant = self.prepare_authorization_code_grant(
                req,
                code_str,
                policy.authorization_code_grant_allowed,
            )?;
            self.issue_validated_authorization_code_grant(
                grant,
                cnf,
                sender_binding,
                policy.issue_refresh_tokens,
            )
            .map_err(Into::into)
        })();
        guard.release();
        result
    }

    async fn try_exchange_authorization_code_grant_async(
        &self,
        req: TokenRequest,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        policy: AuthorizationCodeGrantPolicy,
    ) -> TokenExchangeResult<TokenResponse> {
        let (req, code_str) = take_authorization_code_request(req)?;
        let guard = self
            .code_store
            .acquire_exchange_lock_async(code_str.clone())
            .await
            .map_err(authorization_code_grant_exchange_lock_error)?;
        let result = async {
            let grant = self
                .prepare_authorization_code_grant_async(
                    req,
                    code_str,
                    policy.authorization_code_grant_allowed,
                )
                .await?;
            self.issue_validated_authorization_code_grant_async(
                grant,
                cnf,
                sender_binding,
                policy.issue_refresh_tokens,
            )
            .await
            .map_err(Into::into)
        }
        .await;
        guard.release_async().await;
        result
    }
}
