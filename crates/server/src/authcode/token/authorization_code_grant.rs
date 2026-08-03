use super::TokenIssuer;
use crate::authcode::types::{CnfClaim, SenderBinding, TokenRequest, TokenResponse};

mod context;
mod error;
mod exchange;
mod finalization;
mod issuance;
mod issue;
mod request;
mod validation;

pub(crate) use error::AuthorizationCodeTokenExchangeError;
use exchange::AuthorizationCodeGrantPolicy;

impl TokenIssuer {
    /// Exchange authorization code for tokens.
    ///
    /// `cnf` is the sender-constraint confirmation method (`DPoP` jkt or mTLS x5t#S256) to embed
    /// in the JWT access token's `cnf` claim per RFC 9068 §3.1.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is structurally invalid or the signing backend cannot
    /// issue a token response.
    pub fn exchange_code_for_tokens(
        &self,
        req: TokenRequest,
        cnf: Option<&CnfClaim>,
    ) -> Result<TokenResponse, String> {
        self.exchange_code_for_tokens_bound(req, cnf, None)
    }

    /// Exchange authorization code for tokens and persist sender-binding metadata atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is structurally invalid or the signing backend cannot
    /// issue a token response.
    pub fn exchange_code_for_tokens_bound(
        &self,
        req: TokenRequest,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
    ) -> Result<TokenResponse, String> {
        self.exchange_code_for_tokens_bound_with_grant_policy(req, cnf, sender_binding, true, true)
    }

    /// Exchange authorization code for tokens with an explicit refresh-token issuance policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is structurally invalid or the signing backend cannot
    /// issue a token response.
    pub fn exchange_code_for_tokens_bound_with_refresh_policy(
        &self,
        req: TokenRequest,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        issue_refresh_tokens: bool,
    ) -> Result<TokenResponse, String> {
        self.exchange_code_for_tokens_bound_with_grant_policy(
            req,
            cnf,
            sender_binding,
            true,
            issue_refresh_tokens,
        )
    }

    /// Exchange authorization code for tokens with explicit token-issue grant policies.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is structurally invalid or the signing backend cannot
    /// issue a token response.
    pub fn exchange_code_for_tokens_bound_with_grant_policy(
        &self,
        req: TokenRequest,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        authorization_code_grant_allowed: bool,
        issue_refresh_tokens: bool,
    ) -> Result<TokenResponse, String> {
        self.exchange_authorization_code_grant(
            req,
            cnf,
            sender_binding,
            AuthorizationCodeGrantPolicy {
                authorization_code_grant_allowed,
                issue_refresh_tokens,
            },
        )
    }

    /// Exchange authorization code for tokens with explicit token-issue grant policies.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is structurally invalid or the signing backend cannot
    /// issue a token response.
    pub async fn exchange_code_for_tokens_bound_with_grant_policy_async(
        &self,
        req: TokenRequest,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        authorization_code_grant_allowed: bool,
        issue_refresh_tokens: bool,
    ) -> Result<TokenResponse, String> {
        self.exchange_authorization_code_grant_async(
            req,
            cnf,
            sender_binding,
            AuthorizationCodeGrantPolicy {
                authorization_code_grant_allowed,
                issue_refresh_tokens,
            },
        )
        .await
    }

    pub(crate) async fn exchange_code_for_tokens_bound_with_grant_policy_for_token_endpoint_async(
        &self,
        req: TokenRequest,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
        authorization_code_grant_allowed: bool,
        issue_refresh_tokens: bool,
    ) -> Result<TokenResponse, AuthorizationCodeTokenExchangeError> {
        self.exchange_authorization_code_grant_for_token_endpoint_async(
            req,
            cnf,
            sender_binding,
            AuthorizationCodeGrantPolicy {
                authorization_code_grant_allowed,
                issue_refresh_tokens,
            },
        )
        .await
    }
}
