#[cfg(test)]
use super::{state_error_to_par_error, try_read_lock, ParStateError};
use super::{ParError, ParRequest, ParStore, ValidatedParRequest};
#[cfg(test)]
use crate::client_registry::verify_client_secret_material;

fn validate_pkce(request: &ParRequest) -> Result<(), ParError> {
    if request.code_challenge.is_none() {
        return Err(ParError {
            error: "invalid_request".to_string(),
            error_description: Some("PKCE (S256) code_challenge required".to_string()),
        });
    }
    if request
        .code_challenge_method
        .as_deref()
        .is_none_or(|method| method != "S256")
    {
        return Err(ParError {
            error: "invalid_request".to_string(),
            error_description: Some("code_challenge_method must be S256".to_string()),
        });
    }
    Ok(())
}

impl ParStore {
    /// Validate client authentication.
    #[cfg(test)]
    fn try_validate_client(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        client_authenticated: bool,
    ) -> Result<bool, ParStateError> {
        let clients = try_read_lock(&self.clients, "clients read")?;
        let secret_credentials = try_read_lock(
            &self.client_secret_credentials,
            "client secret credentials read",
        )?;
        Ok(match clients.get(client_id) {
            Some(client) => {
                let method = client.token_endpoint_auth_method.trim();
                if method.eq_ignore_ascii_case("none") {
                    if let Some(provided) = client_secret {
                        let _ = verify_client_secret_material(None, &[], provided);
                    }
                    client_secret.is_none()
                        && client.client_secret.is_none()
                        && !secret_credentials.contains_key(client_id)
                } else if method.eq_ignore_ascii_case("client_secret_basic")
                    || method.eq_ignore_ascii_case("client_secret_post")
                {
                    client_secret.is_some_and(|provided| {
                        verify_client_secret_material(
                            client.client_secret.as_deref(),
                            secret_credentials.get(client_id).map_or(&[], Vec::as_slice),
                            provided,
                        )
                    })
                } else {
                    if let Some(provided) = client_secret {
                        let _ = verify_client_secret_material(None, &[], provided);
                    }
                    client_authenticated && client_secret.is_none()
                }
            }
            None => {
                if let Some(provided) = client_secret {
                    let _ = verify_client_secret_material(None, &[], provided);
                }
                false
            }
        })
    }

    /// Validate redirect URI against client registry.
    #[cfg(test)]
    pub(super) fn try_validate_redirect_uri(
        &self,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<bool, ParStateError> {
        let clients = try_read_lock(&self.clients, "clients read")?;
        Ok(clients
            .get(client_id)
            .is_some_and(|client| client.redirect_uris.iter().any(|uri| uri == redirect_uri)))
    }

    /// Validate requested scopes against client policy.
    #[cfg(test)]
    pub(super) fn try_validate_scopes(
        &self,
        client_id: &str,
        scope: Option<&str>,
    ) -> Result<bool, ParStateError> {
        let Some(scope_str) = scope else {
            return Ok(true);
        };
        let clients = try_read_lock(&self.clients, "clients read")?;
        Ok(if let Some(client) = clients.get(client_id) {
            scope_str
                .split_whitespace()
                .all(|s| client.allowed_scopes.iter().any(|allowed| allowed == s))
        } else {
            false
        })
    }

    #[cfg(test)]
    fn validate_test_process_local_client(&self, request: &ParRequest) -> Result<(), ParError> {
        if !self
            .try_validate_client(
                &request.client_id,
                request.client_secret.as_deref(),
                request.client_authenticated,
            )
            .map_err(|err| state_error_to_par_error(&err))?
        {
            return Err(ParError {
                error: "invalid_client".to_string(),
                error_description: Some("Client authentication failed".to_string()),
            });
        }

        if !self
            .try_validate_redirect_uri(&request.client_id, &request.redirect_uri)
            .map_err(|err| state_error_to_par_error(&err))?
        {
            return Err(ParError {
                error: "invalid_request".to_string(),
                error_description: Some("Invalid redirect_uri".to_string()),
            });
        }

        if !self
            .try_validate_scopes(&request.client_id, request.scope.as_deref())
            .map_err(|err| state_error_to_par_error(&err))?
        {
            return Err(ParError {
                error: "invalid_scope".to_string(),
                error_description: Some("Requested scope is not allowed".to_string()),
            });
        }

        Ok(())
    }

    pub(super) fn validate_request(
        &self,
        request: ParRequest,
    ) -> Result<ValidatedParRequest, ParError> {
        #[cfg(test)]
        self.validate_test_process_local_client(&request)?;
        validate_pkce(&request)?;

        Ok(ValidatedParRequest::new(request))
    }
}
