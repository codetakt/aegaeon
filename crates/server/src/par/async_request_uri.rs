use super::*;
use crate::organizations::request_work::async_store::blocking;
use std::sync::atomic::Ordering;

fn worker_unavailable() -> ParError {
    ParError {
        error: "server_error".into(),
        error_description: Some("PAR store worker unavailable".into()),
    }
}

fn client_mismatch() -> ParError {
    ParError {
        error: "invalid_request".into(),
        error_description: Some("request_uri client_id mismatch".into()),
    }
}

impl ParStore {
    pub(super) async fn store_request_async(
        self: Arc<Self>,
        request: ValidatedParRequest,
        jti: Option<crate::authcode::store::RequestObjectJtiAuthorizationCodeCommit>,
    ) -> Result<ParResponse, ParError> {
        let Some(backend) = self.request_store.postgres() else {
            if jti.is_some() {
                return Err(worker_unavailable());
            }
            return blocking(move || self.store_request(request))
                .await
                .map_err(|_| worker_unavailable())?;
        };
        let request = request.into_inner();
        let expires_in = self.expires_in.load(Ordering::Relaxed);
        let expires_at = SystemTime::now()
            .checked_add(Duration::from_secs(expires_in))
            .ok_or_else(worker_unavailable)?;
        let uri = Self::generate_request_uri();
        let stored = StoredParRequest {
            client_id: request.client_id.clone(),
            request,
            expires_at,
            authorize_continuation: None,
        };
        backend
            .insert_with_jti(&uri, stored, jti)
            .await
            .map_err(|error| storage_error_to_par_error(&error))?;
        Ok(ParResponse {
            request_uri: uri,
            expires_in,
        })
    }

    pub(crate) async fn reserve_request_for_client_async(
        self: Arc<Self>,
        request_uri: String,
        client_id: String,
    ) -> Result<ReservedParRequest, ParError> {
        let Some(backend) = self.request_store.postgres() else {
            return blocking(move || self.reserve_request_for_client(&request_uri, &client_id))
                .await
                .map_err(|_| worker_unavailable())?;
        };
        let continuation = Self::generate_authorize_continuation();
        match backend
            .reserve(&request_uri, &client_id, &continuation)
            .await
            .map_err(|error| storage_error_to_par_error(&error))?
        {
            storage::PostgresLookup::Found(stored) => Ok(ReservedParRequest {
                request: stored.request,
                continuation,
            }),
            storage::PostgresLookup::Missing => Err(invalid_request_uri_error()),
            storage::PostgresLookup::ClientMismatch => Err(client_mismatch()),
        }
    }

    pub(crate) async fn resume_request_for_client_async(
        self: Arc<Self>,
        request_uri: String,
        client_id: String,
        continuation: String,
    ) -> Result<ParRequest, ParError> {
        let Some(backend) = self.request_store.postgres() else {
            return blocking(move || {
                self.resume_request_for_client(&request_uri, &client_id, &continuation)
            })
            .await
            .map_err(|_| worker_unavailable())?;
        };
        let stored = backend
            .load(&request_uri)
            .await
            .map_err(|error| storage_error_to_par_error(&error))?
            .ok_or_else(invalid_request_uri_error)?;
        if stored.client_id != client_id {
            return Err(client_mismatch());
        }
        if !stored
            .authorize_continuation
            .as_ref()
            .is_some_and(|current| {
                crate::util::constant_time_eq(current.as_bytes(), continuation.as_bytes())
            })
        {
            return Err(invalid_request_uri_error());
        }
        Ok(stored.request)
    }

    pub async fn try_consume_request_async(
        self: Arc<Self>,
        request_uri: String,
    ) -> Result<Option<ParRequest>, ParError> {
        let Some(backend) = self.request_store.postgres() else {
            return blocking(move || self.try_consume_request(&request_uri))
                .await
                .map_err(|_| worker_unavailable())?;
        };
        backend
            .consume(&request_uri)
            .await
            .map(|stored| stored.map(|stored| stored.request))
            .map_err(|error| storage_error_to_par_error(&error))
    }

    pub async fn cleanup_async(self: Arc<Self>) -> Result<(), ParError> {
        let Some(backend) = self.request_store.postgres() else {
            return blocking(move || self.try_cleanup_expired())
                .await
                .map_err(|_| worker_unavailable())?;
        };
        backend
            .cleanup()
            .await
            .map_err(|error| storage_error_to_par_error(&error))
    }
}
