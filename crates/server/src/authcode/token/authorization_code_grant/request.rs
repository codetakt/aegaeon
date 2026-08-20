use super::super::TokenIssuer;
use super::context::ValidatedAuthorizationCodeGrant;
use super::error::{TokenExchangeError, TokenExchangeResult, TokenGrantError, TokenGrantErrorCode};
use super::validation::{self, ValidatedCodeGrantRequest};
use crate::authcode::types::{AuthorizationCode, TokenRequest};

impl TokenIssuer {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the grant handler owns the parsed token request at this boundary"
    )]
    pub(super) fn prepare_authorization_code_grant(
        &self,
        req: TokenRequest,
        code_str: String,
        authorization_code_grant_allowed: bool,
    ) -> TokenExchangeResult<ValidatedAuthorizationCodeGrant> {
        let code = self.load_authorization_code_for_exchange(&code_str)?;
        let ValidatedCodeGrantRequest {
            selected_resource,
            openid_requested,
        } = validation::validate_code_grant_request(
            &req,
            &code,
            authorization_code_grant_allowed,
            self.oidc.is_some(),
        )?;
        Ok(ValidatedAuthorizationCodeGrant {
            code_str,
            code,
            selected_resource,
            openid_requested,
        })
    }

    pub(super) async fn prepare_authorization_code_grant_async(
        &self,
        req: TokenRequest,
        code_str: String,
        authorization_code_grant_allowed: bool,
    ) -> TokenExchangeResult<ValidatedAuthorizationCodeGrant> {
        let code = self
            .load_authorization_code_for_exchange_async(code_str.clone())
            .await?;
        let ValidatedCodeGrantRequest {
            selected_resource,
            openid_requested,
        } = validation::validate_code_grant_request(
            &req,
            &code,
            authorization_code_grant_allowed,
            self.oidc.is_some(),
        )?;
        Ok(ValidatedAuthorizationCodeGrant {
            code_str,
            code,
            selected_resource,
            openid_requested,
        })
    }

    fn load_authorization_code_for_exchange(
        &self,
        code_str: &str,
    ) -> TokenExchangeResult<AuthorizationCode> {
        match self.code_store.try_get_code(code_str) {
            Ok(Some(code)) => Ok(code),
            Ok(None) => Err(TokenExchangeError::invalid_or_expired_code()),
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "authorization code store lookup failed during token exchange"
                );
                Err(TokenGrantError::server("authorization code store unavailable").into())
            }
        }
    }

    async fn load_authorization_code_for_exchange_async(
        &self,
        code_str: String,
    ) -> TokenExchangeResult<AuthorizationCode> {
        match self.code_store.try_get_code_async(code_str).await {
            Ok(Some(code)) => Ok(code),
            Ok(None) => Err(TokenExchangeError::invalid_or_expired_code()),
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "authorization code store lookup failed during token exchange"
                );
                Err(TokenGrantError::server("authorization code store unavailable").into())
            }
        }
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "this function is an owned Result::map_err callback"
)]
pub(super) fn authorization_code_grant_exchange_lock_error(error: String) -> TokenExchangeError {
    TokenGrantError::server(format!(
        "authorization-code grant exchange lock unavailable: {error}"
    ))
    .into()
}

pub(super) fn take_authorization_code_request(
    mut req: TokenRequest,
) -> TokenExchangeResult<(TokenRequest, String)> {
    ensure_authorization_code_grant_type(&req)?;
    let code = req
        .code
        .take()
        .ok_or_else(TokenExchangeError::missing_code)?;
    Ok((req, code))
}

fn ensure_authorization_code_grant_type(req: &TokenRequest) -> Result<(), TokenGrantError> {
    (req.grant_type == "authorization_code")
        .then_some(())
        .ok_or_else(|| {
            TokenGrantError::without_description(TokenGrantErrorCode::UnsupportedGrantType)
        })
}
