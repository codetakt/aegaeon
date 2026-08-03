use super::{
    access_token_expires_at, scope_contains, split_scopes, validate_optional_resource_indicator,
    BearerAccessTokenMint, TokenIssuer,
};
use crate::authcode::types::{
    AccessToken, BearerTokenMeta, BearerTokenMetaInput, CnfClaim, SenderBinding, TokenResponse,
};
use std::{borrow::Cow, time::SystemTime};

#[derive(Clone, Copy)]
enum SubjectTokenGrantKind {
    ClientCredentials,
    JwtBearer,
}

impl SubjectTokenGrantKind {
    fn openid_error_description(self) -> &'static str {
        match self {
            Self::ClientCredentials => {
                "openid scope is not allowed for the client_credentials grant"
            }
            Self::JwtBearer => "openid scope is not allowed for the jwt-bearer grant",
        }
    }
}

struct SubjectTokenGrantRequest<'a> {
    kind: SubjectTokenGrantKind,
    client_id: &'a str,
    subject: &'a str,
    scope: Option<String>,
    resource: Option<&'a str>,
    cnf: Option<&'a CnfClaim>,
    sender_binding: Option<&'a SenderBinding>,
}

struct PreparedSubjectToken {
    access_token: AccessToken,
    meta: BearerTokenMeta,
    scope: Option<String>,
    expires_in: u64,
}

struct SubjectTokenGrantError {
    error: &'static str,
    error_description: Option<Cow<'static, str>>,
}

impl SubjectTokenGrantError {
    fn described(error: &'static str, error_description: impl Into<Cow<'static, str>>) -> Self {
        Self {
            error,
            error_description: Some(error_description.into()),
        }
    }

    fn invalid_scope(kind: SubjectTokenGrantKind) -> Self {
        Self::described("invalid_scope", kind.openid_error_description())
    }

    fn invalid_target(error_description: String) -> Self {
        Self::described("invalid_target", error_description)
    }

    fn server(error_description: impl Into<Cow<'static, str>>) -> Self {
        Self::described("server_error", error_description)
    }

    fn into_token_response(self) -> TokenResponse {
        TokenResponse::Error {
            error: self.error.to_string(),
            error_description: self.error_description.map(Cow::into_owned),
        }
    }
}

impl TokenIssuer {
    /// Issue an access token using the Client Credentials grant (RFC 6749 §4.4).
    ///
    /// # Errors
    ///
    /// Returns an error when the signing backend cannot mint the access token.
    pub fn issue_client_credentials_token(
        &self,
        client_id: &str,
        scope: Option<String>,
        resource: Option<&str>,
        cnf: Option<&CnfClaim>,
    ) -> Result<TokenResponse, String> {
        self.issue_client_credentials_token_bound(client_id, scope, resource, cnf, None)
    }

    /// Issue a client-credentials access token with persisted sender-binding metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the signing backend cannot mint the access token.
    pub fn issue_client_credentials_token_bound(
        &self,
        client_id: &str,
        scope: Option<String>,
        resource: Option<&str>,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
    ) -> Result<TokenResponse, String> {
        self.issue_subject_token(SubjectTokenGrantRequest {
            kind: SubjectTokenGrantKind::ClientCredentials,
            client_id,
            subject: client_id,
            scope,
            resource,
            cnf,
            sender_binding,
        })
    }

    /// Issue a client-credentials access token with persisted sender-binding metadata,
    /// committing token-store state on the blocking worker pool.
    ///
    /// # Errors
    ///
    /// Returns an error when the signing backend cannot mint the access token.
    pub async fn issue_client_credentials_token_bound_async(
        &self,
        client_id: String,
        scope: Option<String>,
        resource: Option<String>,
        cnf: Option<CnfClaim>,
        sender_binding: Option<SenderBinding>,
    ) -> Result<TokenResponse, String> {
        self.issue_subject_token_async(SubjectTokenGrantRequest {
            kind: SubjectTokenGrantKind::ClientCredentials,
            client_id: &client_id,
            subject: &client_id,
            scope,
            resource: resource.as_deref(),
            cnf: cnf.as_ref(),
            sender_binding: sender_binding.as_ref(),
        })
        .await
    }

    /// Issue an access token using the JWT Bearer grant (RFC 7523 §2.1).
    ///
    /// The caller is responsible for validating the JWT assertion (signature + claims) and
    /// passing the resulting `subject` into this method.
    ///
    /// # Errors
    ///
    /// Returns an error when the signing backend cannot mint the access token.
    pub fn issue_jwt_bearer_token(
        &self,
        client_id: &str,
        subject: &str,
        scope: Option<String>,
        resource: Option<&str>,
        cnf: Option<&CnfClaim>,
    ) -> Result<TokenResponse, String> {
        self.issue_jwt_bearer_token_bound(client_id, subject, scope, resource, cnf, None)
    }

    /// Issue a JWT bearer grant access token with persisted sender-binding metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the signing backend cannot mint the access token.
    pub fn issue_jwt_bearer_token_bound(
        &self,
        client_id: &str,
        subject: &str,
        scope: Option<String>,
        resource: Option<&str>,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
    ) -> Result<TokenResponse, String> {
        self.issue_subject_token(SubjectTokenGrantRequest {
            kind: SubjectTokenGrantKind::JwtBearer,
            client_id,
            subject,
            scope,
            resource,
            cnf,
            sender_binding,
        })
    }

    /// Issue a JWT bearer grant access token with persisted sender-binding metadata,
    /// committing token-store state on the blocking worker pool.
    ///
    /// # Errors
    ///
    /// Returns an error when the signing backend cannot mint the access token.
    pub async fn issue_jwt_bearer_token_bound_async(
        &self,
        client_id: String,
        subject: String,
        scope: Option<String>,
        resource: Option<String>,
        cnf: Option<CnfClaim>,
        sender_binding: Option<SenderBinding>,
    ) -> Result<TokenResponse, String> {
        self.issue_subject_token_async(SubjectTokenGrantRequest {
            kind: SubjectTokenGrantKind::JwtBearer,
            client_id: &client_id,
            subject: &subject,
            scope,
            resource: resource.as_deref(),
            cnf: cnf.as_ref(),
            sender_binding: sender_binding.as_ref(),
        })
        .await
    }

    fn issue_subject_token(
        &self,
        req: SubjectTokenGrantRequest<'_>,
    ) -> Result<TokenResponse, String> {
        let prepared = match self.prepare_subject_token(req) {
            Ok(prepared) => prepared,
            Err(error) => return Ok(error.into_token_response()),
        };
        let (access_token_str, _) =
            match self
                .token_store
                .store_issued_grant(prepared.access_token, None, prepared.meta)
            {
                Ok(stored) => stored,
                Err(err) => {
                    return Ok(TokenResponse::Error {
                        error: "server_error".to_string(),
                        error_description: Some(err),
                    });
                }
            };

        Ok(TokenResponse::Success {
            access_token: access_token_str,
            token_type: "Bearer".to_string(),
            expires_in: prepared.expires_in,
            refresh_token: None,
            scope: prepared.scope,
            id_token: None,
            authorization_details: None,
        })
    }

    async fn issue_subject_token_async(
        &self,
        req: SubjectTokenGrantRequest<'_>,
    ) -> Result<TokenResponse, String> {
        let prepared = match self.prepare_subject_token(req) {
            Ok(prepared) => prepared,
            Err(error) => return Ok(error.into_token_response()),
        };
        let (access_token_str, _) = match self
            .token_store
            .store_issued_grant_async(prepared.access_token, None, prepared.meta)
            .await
        {
            Ok(stored) => stored,
            Err(err) => {
                return Ok(TokenResponse::Error {
                    error: "server_error".to_string(),
                    error_description: Some(err),
                });
            }
        };

        Ok(TokenResponse::Success {
            access_token: access_token_str,
            token_type: "Bearer".to_string(),
            expires_in: prepared.expires_in,
            refresh_token: None,
            scope: prepared.scope,
            id_token: None,
            authorization_details: None,
        })
    }

    fn prepare_subject_token(
        &self,
        req: SubjectTokenGrantRequest<'_>,
    ) -> Result<PreparedSubjectToken, SubjectTokenGrantError> {
        let SubjectTokenGrantRequest {
            kind,
            client_id,
            subject,
            scope,
            resource,
            cnf,
            sender_binding,
        } = req;

        if scope_contains(scope.as_deref(), "openid") {
            return Err(SubjectTokenGrantError::invalid_scope(kind));
        }

        let resource = match validate_optional_resource_indicator(resource) {
            Ok(value) => value,
            Err(err) => {
                return Err(SubjectTokenGrantError::invalid_target(err));
            }
        };

        let expires_in = self.access_token_ttl_secs;
        let now = SystemTime::now();
        let expires_at = match access_token_expires_at(now, expires_in) {
            Ok(expires_at) => expires_at,
            Err(()) => {
                return Err(SubjectTokenGrantError::server(
                    "access token expiry is outside representable time",
                ));
            }
        };
        let audience = resource.unwrap_or_else(|| client_id.to_string());
        let access_token_str = match self.issue_access_token_value(BearerAccessTokenMint {
            subject,
            client_id,
            scope: scope.as_deref(),
            audience: &audience,
            issued_at: now,
            expires_in,
            auth_time_epoch_secs: None,
            acr: None,
            cnf,
        }) {
            Ok(token) => token,
            Err(err) => {
                return Err(SubjectTokenGrantError::server(err));
            }
        };

        let access_token = AccessToken {
            token: access_token_str.clone(),
            token_type: "Bearer".to_string(),
            client_id: client_id.to_string(),
            user_id: subject.to_string(),
            scope: scope.clone(),
            expires_in,
            created_at: now,
            cnf: cnf.cloned(),
        };

        let meta = BearerTokenMeta::new(BearerTokenMetaInput {
            token_id: access_token_str.clone(),
            client_id: client_id.to_string(),
            user_id: subject.to_string(),
            granted_scopes: split_scopes(scope.as_deref()),
            audience,
            sender_binding: sender_binding.cloned(),
            authorization_details: None,
            auth_time_epoch_secs: None,
            acr: None,
            issued_at: now,
            expires_at,
            refresh_parent: None,
        });

        Ok(PreparedSubjectToken {
            access_token,
            meta,
            scope,
            expires_in,
        })
    }
}
