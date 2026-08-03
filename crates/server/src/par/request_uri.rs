use super::{
    invalid_request_uri_error, remaining_ttl, storage_error_to_par_error, ParError, ParRequest,
    ParResponse, ParStore, ReservedParRequest, StoredParRequest, ValidatedParRequest,
};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

impl ParStore {
    /// Generate a unique `request_uri`.
    pub(crate) fn generate_request_uri() -> String {
        format!(
            "urn:aegaeon:par:{}",
            aegaeon_crypto::rand::random_base64url(32)
        )
    }

    fn generate_authorize_continuation() -> String {
        aegaeon_crypto::rand::random_base64url(32)
    }

    /// Store a validated PAR request.
    ///
    /// # Errors
    ///
    /// Returns a `ParError` when the request cannot be persisted.
    pub(super) fn store_request(
        &self,
        request: ValidatedParRequest,
    ) -> Result<ParResponse, ParError> {
        let request = request.into_inner();
        let request_uri = Self::generate_request_uri();
        let expires_in = self.expires_in.load(Ordering::Relaxed).max(1);
        let expires_at = SystemTime::now()
            .checked_add(Duration::from_secs(expires_in))
            .ok_or_else(|| ParError {
                error: "server_error".to_string(),
                error_description: Some("PAR request expiry overflow".to_string()),
            })?;

        let stored = StoredParRequest {
            client_id: request.client_id.clone(),
            request,
            expires_at,
            authorize_continuation: None,
        };

        self.request_store
            .insert(&request_uri, stored, Duration::from_secs(expires_in))
            .map_err(|err| storage_error_to_par_error(&err))?;

        Ok(ParResponse {
            request_uri,
            expires_in,
        })
    }

    #[cfg(test)]
    pub(crate) fn set_expires_in(&self, seconds: u64) {
        self.expires_in.store(seconds.max(1), Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn insert_stored_request_for_test(
        &self,
        request_uri: &str,
        stored: StoredParRequest,
    ) -> Result<(), String> {
        self.request_store
            .insert(request_uri, stored, Duration::from_secs(1))
            .map_err(|err| format!("test PAR request store should accept inserted request: {err}"))
    }

    pub(super) fn stored_request_is_releasable(&self, stored: &StoredParRequest) -> bool {
        SystemTime::now() < stored.expires_at
    }

    fn purge_invalid_request_uri(&self, request_uri: &str) -> Result<(), ParError> {
        self.request_store
            .remove(request_uri)
            .map_err(|err| storage_error_to_par_error(&err))
    }

    pub fn try_consume_request(&self, request_uri: &str) -> Result<Option<ParRequest>, ParError> {
        let Some(stored) = self
            .request_store
            .consume(request_uri)
            .map_err(|err| storage_error_to_par_error(&err))?
        else {
            return Ok(None);
        };

        Ok(self
            .stored_request_is_releasable(&stored)
            .then_some(stored.request))
    }

    /// Reserve a PAR request for its first front-channel `/authorize` use.
    pub fn reserve_request_for_client(
        &self,
        request_uri: &str,
        expected_client_id: &str,
    ) -> Result<ReservedParRequest, ParError> {
        let Some(stored) = self
            .request_store
            .load(request_uri)
            .map_err(|err| storage_error_to_par_error(&err))?
        else {
            return Err(invalid_request_uri_error());
        };
        if !self.stored_request_is_releasable(&stored) {
            self.purge_invalid_request_uri(request_uri)?;
            return Err(invalid_request_uri_error());
        }
        if stored.client_id != expected_client_id {
            return Err(ParError {
                error: "invalid_request".to_string(),
                error_description: Some("request_uri client_id mismatch".to_string()),
            });
        }

        let Some(ttl) = remaining_ttl(stored.expires_at) else {
            self.purge_invalid_request_uri(request_uri)?;
            return Err(invalid_request_uri_error());
        };
        let continuation = Self::generate_authorize_continuation();
        if !self
            .request_store
            .reserve(request_uri, &continuation, ttl)
            .map_err(|err| storage_error_to_par_error(&err))?
        {
            return Err(invalid_request_uri_error());
        }

        let Some(stored) = self
            .request_store
            .load(request_uri)
            .map_err(|err| storage_error_to_par_error(&err))?
        else {
            self.purge_invalid_request_uri(request_uri)?;
            return Err(invalid_request_uri_error());
        };
        if !self.stored_request_is_releasable(&stored) || stored.client_id != expected_client_id {
            self.purge_invalid_request_uri(request_uri)?;
            return Err(invalid_request_uri_error());
        }

        Ok(ReservedParRequest {
            request: stored.request,
            continuation,
        })
    }

    /// Resume a reserved PAR request during a local-login continuation.
    pub fn resume_request_for_client(
        &self,
        request_uri: &str,
        expected_client_id: &str,
        continuation: &str,
    ) -> Result<ParRequest, ParError> {
        let Some(stored) = self
            .request_store
            .load(request_uri)
            .map_err(|err| storage_error_to_par_error(&err))?
        else {
            return Err(invalid_request_uri_error());
        };
        if !self.stored_request_is_releasable(&stored) {
            self.purge_invalid_request_uri(request_uri)?;
            return Err(invalid_request_uri_error());
        }
        if stored.client_id != expected_client_id {
            return Err(ParError {
                error: "invalid_request".to_string(),
                error_description: Some("request_uri client_id mismatch".to_string()),
            });
        }
        if self
            .request_store
            .reservation(request_uri)
            .map_err(|err| storage_error_to_par_error(&err))?
            .as_deref()
            != Some(continuation)
        {
            return Err(invalid_request_uri_error());
        }

        Ok(stored.request)
    }

    pub fn try_authorize_continuation(
        &self,
        request_uri: &str,
    ) -> Result<Option<String>, ParError> {
        let Some(stored) = self
            .request_store
            .load(request_uri)
            .map_err(|err| storage_error_to_par_error(&err))?
        else {
            return Ok(None);
        };
        if !self.stored_request_is_releasable(&stored) {
            return Ok(None);
        }
        self.request_store
            .reservation(request_uri)
            .map_err(|err| storage_error_to_par_error(&err))
    }

    pub async fn try_authorize_continuation_async(
        self: std::sync::Arc<Self>,
        request_uri: String,
    ) -> Result<Option<String>, ParError> {
        tokio::task::spawn_blocking(move || self.try_authorize_continuation(&request_uri))
            .await
            .map_err(|err| ParError {
                error: "server_error".to_string(),
                error_description: Some(format!("PAR request store worker failed: {err}")),
            })?
    }

    /// Clean up expired requests.
    pub fn try_cleanup_expired(&self) -> Result<(), ParError> {
        self.request_store
            .cleanup_expired()
            .map_err(|err| ParError {
                error: "server_error".to_string(),
                error_description: Some(format!("PAR request store cleanup failed: {err}")),
            })
    }

    /// Clean up expired requests.
    #[cfg(test)]
    pub fn cleanup_expired(&self) {
        self.try_cleanup_expired()
            .expect("test PAR cleanup should succeed");
    }
}
