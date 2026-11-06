use super::*;
use crate::authcode::code_store::{
    ParAuthorizationCodeCommit, RequestObjectJtiAuthorizationCodeCommit,
};

struct Inputs<'a> {
    par: Option<&'a [u8]>,
    continuation: Option<&'a str>,
    jti: Option<&'a [u8]>,
    jti_ms: Option<i64>,
}

impl PostgresAuthCodeBackend {
    fn inputs<'a>(
        &self,
        inputs: &'a AuthorizationCodeOneTimeInputCommit,
        client_id: &str,
    ) -> Result<Inputs<'a>, StoreCodeError> {
        let (par, continuation) = match &inputs.par {
            Some(ParAuthorizationCodeCommit::Postgres {
                database,
                request_digest,
                expected_continuation,
            }) if self.database.same_database(database) => (
                Some(request_digest.as_slice()),
                Some(expected_continuation.as_str()),
            ),
            None => (None, None),
            Some(_) => return Err(unavailable().into()),
        };
        let (jti, jti_ms) = match &inputs.request_object_jti {
            Some(RequestObjectJtiAuthorizationCodeCommit::Postgres {
                database,
                digest,
                client_digest,
                ttl_ms,
            }) if self.database.same_database(database)
                && crate::util::constant_time_eq(
                    client_digest,
                    &sha256_digest(client_id.as_bytes()),
                ) =>
            {
                (Some(digest.as_slice()), Some(*ttl_ms))
            }
            None => (None, None),
            Some(_) => return Err(unavailable().into()),
        };
        Ok(Inputs {
            par,
            continuation,
            jti,
            jti_ms,
        })
    }

    pub(in crate::authcode) async fn issue(
        &self,
        code: AuthorizationCode,
        inputs: AuthorizationCodeOneTimeInputCommit,
    ) -> Result<String, StoreCodeError> {
        let inputs = self.inputs(&inputs, &code.client_id)?;
        if code.used || code.is_expired() {
            return Err(StoreCodeError::Expired);
        }
        let expiry = expiry_micros(code.expires_at)?;
        let payload = serde_json::to_string(&code).map_err(|_| unavailable())?;
        if payload.len() > 1_048_576 || code.code.is_empty() || code.client_id.is_empty() {
            return Err(unavailable().into());
        }
        let digest = sha256_digest(code.code.as_bytes());
        let client = sha256_digest(code.client_id.as_bytes());
        let state = code
            .state
            .as_ref()
            .map(|state| sha256_digest(state.as_bytes()));
        let nonce = code
            .nonce
            .as_ref()
            .map(|nonce| sha256_digest(nonce.as_bytes()));
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            sqlx::query_scalar::<_, i32>("SELECT aegaeon.issue_runtime_authorization_code($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
                .bind(self.database.namespace.as_ref()).bind(digest.as_slice()).bind(client.as_slice()).bind(payload).bind(expiry)
                .bind(state.as_ref().map(|value| value.as_slice())).bind(nonce.as_ref().map(|value| value.as_slice())).bind(self.observation_ms)
                .bind(inputs.par).bind(inputs.continuation).bind(inputs.jti).bind(inputs.jti_ms)
                .fetch_one(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        match result? {
            0 => Ok(code.code),
            1 => Err(StoreCodeError::CodeCollision),
            2 => Err(StoreCodeError::PushedAuthorizationRequestMissing),
            3 => Err(StoreCodeError::RequestObjectJtiReplay),
            4 => Err(StoreCodeError::Expired),
            _ => Err(unavailable().into()),
        }
    }
}
