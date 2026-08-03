use super::ParStorageError;
use crate::par::{ParRequest, StoredParRequest};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct StoredParRequestRecord {
    request: ParRequest,
    expires_at_epoch_secs: u64,
    client_id: String,
}

impl TryFrom<StoredParRequest> for StoredParRequestRecord {
    type Error = ParStorageError;

    fn try_from(stored: StoredParRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            request: stored.request,
            expires_at_epoch_secs: system_time_to_epoch_secs(stored.expires_at)?,
            client_id: stored.client_id,
        })
    }
}

impl TryFrom<StoredParRequestRecord> for StoredParRequest {
    type Error = ParStorageError;

    fn try_from(record: StoredParRequestRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            request: record.request,
            expires_at: epoch_secs_to_system_time(record.expires_at_epoch_secs)?,
            client_id: record.client_id,
            authorize_continuation: None,
        })
    }
}

fn system_time_to_epoch_secs(time: SystemTime) -> Result<u64, ParStorageError> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ParStorageError::ExpiryOutOfRange)
}

fn epoch_secs_to_system_time(seconds: u64) -> Result<SystemTime, ParStorageError> {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or(ParStorageError::ExpiryOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_stored_request() -> StoredParRequest {
        StoredParRequest {
            request: ParRequest {
                client_id: "client".to_string(),
                redirect_uri: "https://client.example/cb".to_string(),
                response_type: "code".to_string(),
                iss: None,
                resource: None,
                state: Some("state".to_string()),
                code_challenge: Some("challenge".to_string()),
                code_challenge_method: Some("S256".to_string()),
                scope: None,
                nonce: None,
                acr_values: None,
                max_age: None,
                authorization_details: None,
                client_secret: None,
                client_authenticated: true,
                request_object: None,
                request_object_claims: None,
            },
            expires_at: SystemTime::now() + Duration::from_secs(60),
            client_id: "client".to_string(),
            authorize_continuation: Some("local".to_string()),
        }
    }

    #[test]
    fn stored_record_roundtrip_drops_process_local_reservation() -> Result<(), String> {
        let record = StoredParRequestRecord::try_from(sample_stored_request()).map_err(|err| {
            format!("sample stored request should encode as a storage record: {err}")
        })?;
        let decoded = StoredParRequest::try_from(record)
            .map_err(|err| format!("storage record should decode: {err}"))?;

        assert_eq!(decoded.client_id, "client");
        assert!(decoded.authorize_continuation.is_none());
        Ok(())
    }
}
