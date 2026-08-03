use super::{
    access_token_expires_at, split_scopes, validate_optional_resource_indicator,
    BearerAccessTokenMint, TokenIssuer,
};
use crate::authcode::store::RefreshRotationError;
use crate::authcode::types::{
    AccessToken, BearerTokenMeta, BearerTokenMetaInput, CnfClaim, RefreshToken, SenderBinding,
    TokenResponse,
};
use serde_json::Value;
use std::time::SystemTime;

struct PreparedRefreshGrant {
    refresh: RefreshToken,
    selected_resource: Option<String>,
}

struct IssuedRefreshGrant {
    access_token: AccessToken,
    new_refresh: RefreshToken,
    meta: BearerTokenMeta,
    expires_in: u64,
    authorization_details: Option<Value>,
}

struct RefreshGrantSuccess {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
    authorization_details: Option<Value>,
}

enum RefreshGrantError {
    InvalidOrRotated,
    Response {
        error: &'static str,
        description: String,
    },
}

impl TokenIssuer {
    /// Refresh access token.
    ///
    /// `cnf` is the sender-constraint confirmation method (`DPoP` jkt or mTLS x5t#S256) to embed in the JWT
    /// access token's `cnf` claim per RFC 9068 §3.1.
    ///
    /// # Errors
    ///
    /// Returns an error when the refresh token is invalid/rotated or the signing backend cannot
    /// issue a replacement access token.
    pub fn refresh_access_token(
        &self,
        refresh_token: &str,
        resource: Option<&str>,
        cnf: Option<&CnfClaim>,
    ) -> Result<TokenResponse, String> {
        self.refresh_access_token_bound(refresh_token, resource, cnf, None)
    }

    /// Refresh access token and persist sender-binding metadata atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the refresh token is invalid/rotated or the signing backend cannot
    /// issue a replacement access token.
    pub fn refresh_access_token_bound(
        &self,
        refresh_token: &str,
        resource: Option<&str>,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
    ) -> Result<TokenResponse, String> {
        let prepared = match self.prepare_refresh_grant(refresh_token, resource) {
            Ok(prepared) => prepared,
            Err(err) => return err.into_result(),
        };
        let issued = match self.issue_refreshed_grant(
            &prepared.refresh,
            prepared.selected_resource.as_deref(),
            cnf,
            sender_binding,
        ) {
            Ok(issued) => issued,
            Err(err) => return err.into_result(),
        };
        let success = match self.persist_refreshed_grant(refresh_token, issued) {
            Ok(success) => success,
            Err(err) => return err.into_result(),
        };

        Ok(TokenResponse::Success {
            access_token: success.access_token,
            token_type: "Bearer".to_string(),
            expires_in: success.expires_in,
            refresh_token: success.refresh_token,
            scope: None,
            id_token: None,
            authorization_details: success.authorization_details,
        })
    }

    /// Refresh access token and persist sender-binding metadata atomically,
    /// using the blocking worker pool for token-store I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when the refresh token is invalid/rotated or the signing backend cannot
    /// issue a replacement access token.
    pub async fn refresh_access_token_bound_async(
        &self,
        refresh_token: String,
        resource: Option<String>,
        cnf: Option<CnfClaim>,
        sender_binding: Option<SenderBinding>,
    ) -> Result<TokenResponse, String> {
        let prepared = match self
            .prepare_refresh_grant_async(refresh_token.clone(), resource.as_deref())
            .await
        {
            Ok(prepared) => prepared,
            Err(err) => return err.into_result(),
        };
        let issued = match self.issue_refreshed_grant(
            &prepared.refresh,
            prepared.selected_resource.as_deref(),
            cnf.as_ref(),
            sender_binding.as_ref(),
        ) {
            Ok(issued) => issued,
            Err(err) => return err.into_result(),
        };
        let success = match self
            .persist_refreshed_grant_async(refresh_token, issued)
            .await
        {
            Ok(success) => success,
            Err(err) => return err.into_result(),
        };

        Ok(TokenResponse::Success {
            access_token: success.access_token,
            token_type: "Bearer".to_string(),
            expires_in: success.expires_in,
            refresh_token: success.refresh_token,
            scope: None,
            id_token: None,
            authorization_details: success.authorization_details,
        })
    }

    /// Refresh access token from a refresh-token grant that the endpoint has already loaded and
    /// validated for the authenticated client and sender binding.
    ///
    /// # Errors
    ///
    /// Returns an error when the prepared grant is invalid for the requested resource, when the
    /// refresh token is concurrently rotated before commit, or when the signing backend cannot
    /// issue a replacement access token.
    pub(crate) async fn refresh_prepared_access_token_bound_async(
        &self,
        previous_refresh_token: String,
        refresh: RefreshToken,
        resource: Option<String>,
        cnf: Option<CnfClaim>,
        sender_binding: Option<SenderBinding>,
    ) -> Result<TokenResponse, String> {
        if previous_refresh_token.as_str() != refresh.token.as_str() {
            return server_error("prepared refresh token mismatch").into_result();
        }
        let prepared = match Self::prepare_loaded_refresh_grant(refresh, resource.as_deref()) {
            Ok(prepared) => prepared,
            Err(err) => return err.into_result(),
        };
        let issued = match self.issue_refreshed_grant(
            &prepared.refresh,
            prepared.selected_resource.as_deref(),
            cnf.as_ref(),
            sender_binding.as_ref(),
        ) {
            Ok(issued) => issued,
            Err(err) => return err.into_result(),
        };
        let success = match self
            .persist_refreshed_grant_async(previous_refresh_token, issued)
            .await
        {
            Ok(success) => success,
            Err(err) => return err.into_result(),
        };

        Ok(TokenResponse::Success {
            access_token: success.access_token,
            token_type: "Bearer".to_string(),
            expires_in: success.expires_in,
            refresh_token: success.refresh_token,
            scope: None,
            id_token: None,
            authorization_details: success.authorization_details,
        })
    }

    fn prepare_refresh_grant(
        &self,
        refresh_token: &str,
        requested_resource: Option<&str>,
    ) -> Result<PreparedRefreshGrant, RefreshGrantError> {
        let refresh = match self.token_store.prepare_refresh_rotation(refresh_token) {
            Ok(refresh) => refresh,
            Err(RefreshRotationError::BackendUnavailable) => {
                return Err(server_error("token store backend unavailable"));
            }
            Err(
                RefreshRotationError::Invalid
                | RefreshRotationError::Expired
                | RefreshRotationError::Reused
                | RefreshRotationError::InconsistentGrant,
            ) => return Err(RefreshGrantError::InvalidOrRotated),
        };
        Self::prepare_loaded_refresh_grant(refresh, requested_resource)
    }

    async fn prepare_refresh_grant_async(
        &self,
        refresh_token: String,
        requested_resource: Option<&str>,
    ) -> Result<PreparedRefreshGrant, RefreshGrantError> {
        let refresh = match self
            .token_store
            .prepare_refresh_rotation_async(refresh_token)
            .await
        {
            Ok(refresh) => refresh,
            Err(RefreshRotationError::BackendUnavailable) => {
                return Err(server_error("token store backend unavailable"));
            }
            Err(
                RefreshRotationError::Invalid
                | RefreshRotationError::Expired
                | RefreshRotationError::Reused
                | RefreshRotationError::InconsistentGrant,
            ) => return Err(RefreshGrantError::InvalidOrRotated),
        };
        Self::prepare_loaded_refresh_grant(refresh, requested_resource)
    }

    fn prepare_loaded_refresh_grant(
        refresh: RefreshToken,
        requested_resource: Option<&str>,
    ) -> Result<PreparedRefreshGrant, RefreshGrantError> {
        let selected_resource =
            select_refresh_resource(refresh.resource.as_deref(), requested_resource)?;

        Ok(PreparedRefreshGrant {
            refresh,
            selected_resource,
        })
    }

    fn issue_refreshed_grant(
        &self,
        refresh: &RefreshToken,
        selected_resource: Option<&str>,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
    ) -> Result<IssuedRefreshGrant, RefreshGrantError> {
        let expires_in = self.access_token_ttl_secs;
        let now = SystemTime::now();
        let expires_at = match access_token_expires_at(now, expires_in) {
            Ok(expires_at) => expires_at,
            Err(()) => {
                return Err(server_error(
                    "access token expiry is outside representable time",
                ));
            }
        };
        let audience = self.access_token_audience(
            &refresh.client_id,
            refresh.scope.as_deref(),
            selected_resource,
        );
        let access_token_str = match self.issue_access_token_value(BearerAccessTokenMint {
            subject: &refresh.user_id,
            client_id: &refresh.client_id,
            scope: refresh.scope.as_deref(),
            audience: &audience,
            issued_at: now,
            expires_in,
            auth_time_epoch_secs: Some(refresh.auth_time_epoch_secs),
            acr: refresh.acr.as_deref(),
            cnf,
        }) {
            Ok(token) => token,
            Err(err) => {
                return Err(server_error(err));
            }
        };
        let access_token = AccessToken {
            token: access_token_str.clone(),
            token_type: "Bearer".to_string(),
            client_id: refresh.client_id.clone(),
            user_id: refresh.user_id.clone(),
            scope: refresh.scope.clone(),
            expires_in,
            created_at: now,
            cnf: cnf.cloned(),
        };

        let mut refresh_to_rotate = refresh.clone();
        let mut new_refresh = refresh_to_rotate.rotate();
        if let Some(sender_binding) = sender_binding {
            new_refresh.sender_binding = Some(sender_binding.clone());
        }

        let authorization_details = refresh.authorization_details.clone();
        let mut meta = BearerTokenMeta::new(BearerTokenMetaInput {
            token_id: access_token_str.clone(),
            client_id: refresh.client_id.clone(),
            user_id: refresh.user_id.clone(),
            granted_scopes: split_scopes(refresh.scope.as_deref()),
            audience,
            sender_binding: sender_binding.cloned(),
            authorization_details: authorization_details.clone(),
            auth_time_epoch_secs: Some(refresh.auth_time_epoch_secs),
            acr: refresh.acr.clone(),
            issued_at: now,
            expires_at,
            refresh_parent: Some(new_refresh.token.clone()),
        });
        meta.claim_release_policy = refresh.claim_release_policy.clone();

        Ok(IssuedRefreshGrant {
            access_token,
            new_refresh,
            meta,
            expires_in,
            authorization_details,
        })
    }

    fn persist_refreshed_grant(
        &self,
        previous_refresh: &str,
        issued: IssuedRefreshGrant,
    ) -> Result<RefreshGrantSuccess, RefreshGrantError> {
        let expires_in = issued.expires_in;
        let authorization_details = issued.authorization_details;
        let (access_token_str, refresh_token) = match self.token_store.store_refreshed_grant(
            previous_refresh,
            issued.access_token,
            issued.new_refresh,
            issued.meta,
        ) {
            Ok((access_token, refresh_token)) => (access_token, Some(refresh_token)),
            Err(
                RefreshRotationError::Invalid
                | RefreshRotationError::Expired
                | RefreshRotationError::Reused,
            ) => {
                return Err(RefreshGrantError::InvalidOrRotated);
            }
            Err(RefreshRotationError::InconsistentGrant) => {
                return Err(server_error("inconsistent refresh grant state"));
            }
            Err(RefreshRotationError::BackendUnavailable) => {
                return Err(server_error("token store backend unavailable"));
            }
        };

        Ok(RefreshGrantSuccess {
            access_token: access_token_str,
            refresh_token,
            expires_in,
            authorization_details,
        })
    }

    async fn persist_refreshed_grant_async(
        &self,
        previous_refresh: String,
        issued: IssuedRefreshGrant,
    ) -> Result<RefreshGrantSuccess, RefreshGrantError> {
        let expires_in = issued.expires_in;
        let authorization_details = issued.authorization_details;
        let (access_token_str, refresh_token) = match self
            .token_store
            .store_refreshed_grant_async(
                previous_refresh,
                issued.access_token,
                issued.new_refresh,
                issued.meta,
            )
            .await
        {
            Ok((access_token, refresh_token)) => (access_token, Some(refresh_token)),
            Err(
                RefreshRotationError::Invalid
                | RefreshRotationError::Expired
                | RefreshRotationError::Reused,
            ) => {
                return Err(RefreshGrantError::InvalidOrRotated);
            }
            Err(RefreshRotationError::InconsistentGrant) => {
                return Err(server_error("inconsistent refresh grant state"));
            }
            Err(RefreshRotationError::BackendUnavailable) => {
                return Err(server_error("token store backend unavailable"));
            }
        };

        Ok(RefreshGrantSuccess {
            access_token: access_token_str,
            refresh_token,
            expires_in,
            authorization_details,
        })
    }
}

impl RefreshGrantError {
    fn into_result(self) -> Result<TokenResponse, String> {
        match self {
            Self::InvalidOrRotated => Err("Invalid or rotated refresh token".to_string()),
            Self::Response { error, description } => Ok(TokenResponse::Error {
                error: error.to_string(),
                error_description: Some(description),
            }),
        }
    }
}

fn server_error(description: impl Into<String>) -> RefreshGrantError {
    RefreshGrantError::Response {
        error: "server_error",
        description: description.into(),
    }
}

fn invalid_target(description: impl Into<String>) -> RefreshGrantError {
    RefreshGrantError::Response {
        error: "invalid_target",
        description: description.into(),
    }
}

fn select_refresh_resource(
    stored_resource: Option<&str>,
    requested_resource: Option<&str>,
) -> Result<Option<String>, RefreshGrantError> {
    let stored = validate_optional_resource_indicator(stored_resource)
        .map_err(|err| invalid_target(format!("stored resource invalid: {err}")))?;
    let requested =
        validate_optional_resource_indicator(requested_resource).map_err(invalid_target)?;

    match (&stored, &requested) {
        (Some(grant), Some(requested)) if grant != requested => Err(invalid_target(
            "requested resource is not permitted by the refresh token grant",
        )),
        _ => Ok(requested.or(stored)),
    }
}
