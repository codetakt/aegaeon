use super::record::StoredParRequestRecord;
use super::scripts::{consume_request_and_reservation_script, reserve_request_if_present_script};
use super::{ParRequestStore, ParStorageError};
use crate::authcode::store::ParAuthorizationCodeCommit;
use crate::config::{RuntimeRedisAtomicGroup, RuntimeStateNamespace};
use crate::par::StoredParRequest;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::sync::Arc;
use std::time::Duration;

pub(in crate::par) struct RedisParRequestStore {
    client: redis::Client,
    url: Arc<str>,
    prefix: Arc<str>,
}

impl RedisParRequestStore {
    pub(in crate::par) fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ParStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                url: Arc::from(url.to_string().into_boxed_str()),
                prefix: Arc::from(
                    namespace
                        .redis_atomic_group_prefix(
                            RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
                            "par",
                            "v1",
                        )
                        .into_boxed_str(),
                ),
            })
            .map_err(|err| ParStorageError::BackendUnavailable(err.to_string()))
    }

    #[cfg(test)]
    pub(in crate::par) fn new_for_tests(url: &str) -> Result<Self, ParStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                url: Arc::from(url.to_string().into_boxed_str()),
                prefix: Arc::from("par:v1"),
            })
            .map_err(|err| ParStorageError::BackendUnavailable(err.to_string()))
    }

    fn connection(&self) -> Result<redis::Connection, ParStorageError> {
        self.client
            .get_connection()
            .map_err(|err| ParStorageError::BackendUnavailable(err.to_string()))
    }

    fn keys(&self, request_uri: &str) -> (String, String) {
        let digest = par_request_uri_digest(request_uri);
        (
            format!("{}:req:{digest}", self.prefix),
            format!("{}:reservation:{digest}", self.prefix),
        )
    }
}

impl ParRequestStore for RedisParRequestStore {
    fn insert(
        &self,
        request_uri: &str,
        stored: StoredParRequest,
        ttl: Duration,
    ) -> Result<(), ParStorageError> {
        let (request_key, _) = self.keys(request_uri);
        let ttl_ms = ttl_millis_i64(ttl)?;
        let record = StoredParRequestRecord::try_from(stored)?;
        let payload = serde_json::to_string(&record)
            .map_err(|err| ParStorageError::Serialize(err.to_string()))?;
        let mut conn = self.connection()?;

        let result: redis::Value = redis::cmd("SET")
            .arg(&request_key)
            .arg(payload)
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query(&mut conn)
            .map_err(|err| ParStorageError::BackendUnavailable(err.to_string()))?;

        match result {
            redis::Value::Okay => Ok(()),
            redis::Value::Nil => Err(ParStorageError::BackendUnavailable(
                "request_uri collision while storing PAR request".to_string(),
            )),
            other => Err(ParStorageError::BackendUnavailable(format!(
                "unexpected SET response: {other:?}"
            ))),
        }
    }

    fn load(&self, request_uri: &str) -> Result<Option<StoredParRequest>, ParStorageError> {
        let (request_key, _) = self.keys(request_uri);
        let mut conn = self.connection()?;
        let payload = redis::cmd("GET")
            .arg(&request_key)
            .query::<Option<String>>(&mut conn)
            .map_err(|err| ParStorageError::BackendUnavailable(err.to_string()))?;
        payload
            .map(|payload| {
                serde_json::from_str::<StoredParRequestRecord>(&payload)
                    .map_err(|err| ParStorageError::Serialize(err.to_string()))
                    .and_then(StoredParRequest::try_from)
            })
            .transpose()
    }

    fn reserve(
        &self,
        request_uri: &str,
        continuation: &str,
        ttl: Duration,
    ) -> Result<bool, ParStorageError> {
        let (request_key, reservation_key) = self.keys(request_uri);
        let ttl_ms = ttl_millis_i64(ttl)?;
        let result = reserve_request_if_present_script()
            .key(request_key)
            .key(reservation_key)
            .arg(continuation)
            .arg(ttl_ms)
            .invoke::<i64>(&mut self.connection()?)
            .map_err(|err| ParStorageError::BackendUnavailable(err.to_string()))?;

        match result {
            1 => Ok(true),
            0 => Ok(false),
            other => Err(ParStorageError::BackendUnavailable(format!(
                "unexpected reserve script response: {other}"
            ))),
        }
    }

    fn reservation(&self, request_uri: &str) -> Result<Option<String>, ParStorageError> {
        let (_, reservation_key) = self.keys(request_uri);
        redis::cmd("GET")
            .arg(&reservation_key)
            .query::<Option<String>>(&mut self.connection()?)
            .map_err(|err| ParStorageError::BackendUnavailable(err.to_string()))
    }

    fn authorization_code_commit_context(
        &self,
        request_uri: &str,
        expected_continuation: &str,
    ) -> Option<ParAuthorizationCodeCommit> {
        let (request_key, reservation_key) = self.keys(request_uri);
        Some(ParAuthorizationCodeCommit {
            url: self.url.clone(),
            request_key,
            reservation_key,
            expected_continuation: expected_continuation.to_string(),
        })
    }

    fn consume(&self, request_uri: &str) -> Result<Option<StoredParRequest>, ParStorageError> {
        let (request_key, reservation_key) = self.keys(request_uri);
        let payload = consume_request_and_reservation_script()
            .key(request_key)
            .key(reservation_key)
            .invoke::<Option<String>>(&mut self.connection()?)
            .map_err(|err| ParStorageError::BackendUnavailable(err.to_string()))?;
        payload
            .map(|payload| {
                serde_json::from_str::<StoredParRequestRecord>(&payload)
                    .map_err(|err| ParStorageError::Serialize(err.to_string()))
                    .and_then(StoredParRequest::try_from)
            })
            .transpose()
    }

    fn remove(&self, request_uri: &str) -> Result<(), ParStorageError> {
        let (request_key, reservation_key) = self.keys(request_uri);
        redis::cmd("DEL")
            .arg(request_key)
            .arg(reservation_key)
            .query::<()>(&mut self.connection()?)
            .map_err(|err| ParStorageError::BackendUnavailable(err.to_string()))
    }

    fn cleanup_expired(&self) -> Result<(), ParStorageError> {
        Ok(())
    }
}

fn ttl_millis_i64(ttl: Duration) -> Result<i64, ParStorageError> {
    ttl.as_millis()
        .try_into()
        .map(|ttl_ms: i64| ttl_ms.max(1))
        .map_err(|_| ParStorageError::RetentionOverflow)
}

fn par_request_uri_digest(request_uri: &str) -> String {
    let mut hasher = aegaeon_crypto::hash::Sha256Hasher::new();
    hasher.update(b"aegaeon:par:v1");
    hasher.update(&(request_uri.len() as u64).to_be_bytes());
    hasher.update(request_uri.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::par::ParRequest;
    use std::time::SystemTime;

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
    fn par_request_uri_digest_is_length_delimited() {
        assert_ne!(par_request_uri_digest("ab"), par_request_uri_digest("a:b"));
    }

    #[test]
    fn ttl_millis_rejects_unrepresentable_ttl() {
        assert!(matches!(
            ttl_millis_i64(Duration::MAX),
            Err(ParStorageError::RetentionOverflow)
        ));
    }

    #[test]
    #[ignore = "requires AEGAEON_TEST_REDIS_URL"]
    fn redis_store_reserves_and_consumes_once() -> Result<(), String> {
        let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
        let Ok(url) = std::env::var(redis_url_env) else {
            return Ok(());
        };
        let store = RedisParRequestStore::new_for_tests(url.trim())
            .map_err(|err| format!("redis test store: {err}"))?;
        let request_uri = format!(
            "urn:aegaeon:test:par:{}",
            aegaeon_crypto::rand::random_base64url(16)
        );
        let ttl = Duration::from_secs(60);
        let _ = store.remove(&request_uri);

        store
            .insert(&request_uri, sample_stored_request(), ttl)
            .map_err(|err| format!("insert PAR request: {err}"))?;
        assert!(store
            .load(&request_uri)
            .map_err(|err| format!("load PAR request: {err}"))?
            .is_some());
        assert!(
            store
                .reserve(&request_uri, "continuation", ttl)
                .map_err(|err| format!("reserve PAR request: {err}"))?,
            "first reservation should win"
        );
        assert!(
            !store
                .reserve(&request_uri, "other", ttl)
                .map_err(|err| format!("reserve PAR request again: {err}"))?,
            "second reservation must not replace the first continuation"
        );
        assert_eq!(
            store
                .reservation(&request_uri)
                .map_err(|err| format!("load reservation: {err}"))?
                .as_deref(),
            Some("continuation")
        );
        assert!(
            store
                .consume(&request_uri)
                .map_err(|err| format!("consume PAR request: {err}"))?
                .is_some(),
            "first consume should return the stored request"
        );
        assert!(
            store
                .consume(&request_uri)
                .map_err(|err| format!("consume PAR request again: {err}"))?
                .is_none(),
            "second consume must observe single-use deletion"
        );
        assert!(store
            .reservation(&request_uri)
            .map_err(|err| format!("reservation should be deleted: {err}"))?
            .is_none());
        Ok(())
    }
}
