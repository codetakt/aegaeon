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
    access_scope: Option<String>,
}

struct IssuedRefreshGrant {
    access_token: AccessToken,
    new_refresh: RefreshToken,
    meta: BearerTokenMeta,
    expires_in: u64,
    authorization_details: Option<Value>,
}

struct RefreshGrantSuccess {
    token_type: String,
    access_token: String,
    scope: Option<String>,
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
            prepared.access_scope.as_deref(),
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
            token_type: success.token_type,
            expires_in: success.expires_in,
            refresh_token: success.refresh_token,
            scope: success.scope,
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
            prepared.access_scope.as_deref(),
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
            token_type: success.token_type,
            expires_in: success.expires_in,
            refresh_token: success.refresh_token,
            scope: success.scope,
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
        requested_scope: Option<String>,
        cnf: Option<CnfClaim>,
        sender_binding: Option<SenderBinding>,
    ) -> Result<TokenResponse, String> {
        if previous_refresh_token.as_str() != refresh.token.as_str() {
            return server_error("prepared refresh token mismatch").into_result();
        }
        let prepared = match self.prepare_loaded_refresh_grant(
            refresh,
            resource.as_deref(),
            requested_scope.as_deref(),
        ) {
            Ok(prepared) => prepared,
            Err(err) => return err.into_result(),
        };
        let issued = match self.issue_refreshed_grant(
            &prepared.refresh,
            prepared.selected_resource.as_deref(),
            prepared.access_scope.as_deref(),
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
            token_type: success.token_type,
            expires_in: success.expires_in,
            refresh_token: success.refresh_token,
            scope: success.scope,
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
        self.prepare_loaded_refresh_grant(refresh, requested_resource, None)
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
        self.prepare_loaded_refresh_grant(refresh, requested_resource, None)
    }

    fn prepare_loaded_refresh_grant(
        &self,
        refresh: RefreshToken,
        requested_resource: Option<&str>,
        requested_scope: Option<&str>,
    ) -> Result<PreparedRefreshGrant, RefreshGrantError> {
        if refresh.authorization_details.is_some() {
            return Err(invalid_grant(
                "grant contains unsupported authorization details; authorize again",
            ));
        }
        let context = refresh.target_context.as_ref().ok_or_else(|| {
            invalid_grant("refresh token has no original target context; authorize again")
        })?;
        if context.version != 1
            || context.audience.is_empty()
            || context.token_issuer != self.issuer
            || context.oidc_issuer.as_deref() != self.oidc.as_ref().map(|cfg| cfg.issuer.as_str())
        {
            return Err(invalid_grant(
                "refresh target context changed; authorize again",
            ));
        }
        let selected_resource = select_refresh_resource(&context.audience, requested_resource)?;

        let access_scope = select_refresh_scope(refresh.scope.as_deref(), requested_scope)?;

        Ok(PreparedRefreshGrant {
            refresh,
            selected_resource,
            access_scope,
        })
    }

    fn issue_refreshed_grant(
        &self,
        refresh: &RefreshToken,
        selected_resource: Option<&str>,
        access_scope: Option<&str>,
        cnf: Option<&CnfClaim>,
        sender_binding: Option<&SenderBinding>,
    ) -> Result<IssuedRefreshGrant, RefreshGrantError> {
        let now = SystemTime::now();
        let expires_in = if let Some(grant) = &refresh.exchange_grant {
            let root = grant
                .root()
                .ok_or_else(|| invalid_grant("missing exchange lineage"))?;
            root.expires_at
                .duration_since(now)
                .ok()
                .map(|duration| duration.as_secs())
                .filter(|seconds| *seconds > 0)
                .ok_or_else(|| invalid_grant("exchange lineage expired"))?
                .min(self.access_token_ttl_secs)
        } else {
            self.access_token_ttl_secs
        };
        let expires_at = match access_token_expires_at(now, expires_in) {
            Ok(expires_at) => expires_at,
            Err(()) => {
                return Err(server_error(
                    "access token expiry is outside representable time",
                ));
            }
        };
        let audience =
            self.access_token_audience(&refresh.client_id, access_scope, selected_resource);
        let access_token_str = match self.issue_access_token_value(BearerAccessTokenMint {
            subject: &refresh.user_id,
            client_id: &refresh.client_id,
            scope: access_scope,
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
            exchange_root: refresh
                .exchange_grant
                .as_ref()
                .and_then(|grant| grant.root())
                .cloned(),
            token: access_token_str.clone(),
            token_type: AccessToken::type_for_confirmation(cnf).to_string(),
            client_id: refresh.client_id.clone(),
            user_id: refresh.user_id.clone(),
            scope: access_scope.map(str::to_owned),
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
            granted_scopes: split_scopes(access_scope),
            audience,
            sender_binding: sender_binding.cloned(),
            authorization_details: authorization_details.clone(),
            auth_time_epoch_secs: Some(refresh.auth_time_epoch_secs),
            acr: refresh.acr.clone(),
            issued_at: now,
            expires_at,
            refresh_parent: Some(new_refresh.token.clone()),
        });
        meta.exchange_grant = refresh
            .exchange_grant
            .as_ref()
            .map(|grant| grant.attenuate(&meta.granted_scopes));
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
        let scope = issued.access_token.scope.clone();
        let token_type = issued.access_token.token_type.clone();
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
            token_type,
            scope,
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
        let scope = issued.access_token.scope.clone();
        let token_type = issued.access_token.token_type.clone();
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
            token_type,
            scope,
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

fn invalid_grant(description: impl Into<String>) -> RefreshGrantError {
    RefreshGrantError::Response {
        error: "invalid_grant",
        description: description.into(),
    }
}

fn select_refresh_resource(
    saved_audience: &str,
    requested_resource: Option<&str>,
) -> Result<Option<String>, RefreshGrantError> {
    let requested =
        validate_optional_resource_indicator(requested_resource).map_err(invalid_target)?;

    // Supplying the saved target explicitly also keeps it stable when a scope
    // change would otherwise select another default during issuance.
    super::resource_selection::restrict_resource(Some(saved_audience), requested.as_deref())
        .map(|selected| selected.map(str::to_owned))
        .ok_or_else(|| {
            invalid_target("requested resource is not permitted by the refresh token grant")
        })
}

/// RFC 6749 sections 3.3 and 6: omission uses the original grant; an explicit
/// scope may only narrow the access token. Replacement refresh scope is unchanged.
fn select_refresh_scope(
    granted: Option<&str>,
    requested: Option<&str>,
) -> Result<Option<String>, RefreshGrantError> {
    let granted_scopes = crate::oauth_scope::parse_optional_scope_string(granted)
        .map_err(|_| invalid_grant("stored refresh scope is invalid; authorize again"))?;
    let Some(requested) = requested else {
        return Ok(granted.map(str::to_owned));
    };
    let requested_scopes = crate::oauth_scope::parse_scope_string(requested)
        .map_err(|_| invalid_scope("requested scope is not a valid scope string"))?;
    if !requested_scopes
        .iter()
        .all(|scope| granted_scopes.contains(scope))
    {
        return Err(invalid_scope("requested scope exceeds the original grant"));
    }
    Ok(Some(requested.to_string()))
}

fn invalid_scope(description: impl Into<String>) -> RefreshGrantError {
    RefreshGrantError::Response {
        error: "invalid_scope",
        description: description.into(),
    }
}
