use super::super::{
    OidcLogoutEvent, OidcSessionContext, OidcSessionGrantCommit, PostgresOidcSessionGrantCommit,
};
use crate::authcode::store::PostgresGrantDatabase;
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use aegaeon_crypto::hash::sha256_digest;
use std::time::Duration;
use uuid::Uuid;

#[path = "postgres/cleanup.rs"]
mod cleanup;
#[path = "postgres/delivery.rs"]
mod delivery;
#[path = "postgres/logout.rs"]
mod logout;
#[cfg(test)]
#[path = "postgres/tests.rs"]
mod tests;

#[derive(Clone)]
pub(super) struct PostgresOidcSessionBackend {
    database: PostgresGrantDatabase,
}

fn unavailable() -> String {
    "OIDC session database unavailable or invalid".into()
}

fn random_uuid() -> Uuid {
    uuid::Builder::from_random_bytes(aegaeon_crypto::rand::random_array()).into_uuid()
}

impl PostgresOidcSessionGrantCommit {
    // Reused by the future token grant transaction on its existing connection.
    pub(crate) async fn bind_on(
        &self,
        connection: &mut sqlx::PgConnection,
        exact: bool,
    ) -> Result<Uuid, String> {
        sqlx::query_scalar("SELECT aegaeon.bind_runtime_oidc_session($1,$2,$3,$4,$5,$6)")
            .bind(self.database.namespace.as_ref())
            .bind(self.auth_digest.as_slice())
            .bind(&self.user_id)
            .bind(self.sid)
            .bind((!self.client_id.is_empty()).then_some(self.client_id.as_str()))
            .bind(exact)
            .fetch_one(connection)
            .await
            .map_err(|_| unavailable())
    }
}

impl PostgresOidcSessionBackend {
    pub(super) fn new(database: PostgresGrantDatabase) -> Self {
        Self { database }
    }

    fn context(
        &self,
        context: OidcSessionContext<'_>,
        client_id: &str,
        sid: Uuid,
    ) -> Result<PostgresOidcSessionGrantCommit, String> {
        if context.user_id.trim().is_empty() || context.auth_session_id.trim().is_empty() {
            return Err(unavailable());
        }
        Ok(PostgresOidcSessionGrantCommit {
            database: self.database.clone(),
            auth_digest: sha256_digest(context.auth_session_id.as_bytes()),
            user_id: context.user_id.into(),
            client_id: client_id.into(),
            sid,
        })
    }

    pub(super) async fn get_or_create(
        &self,
        context: OidcSessionContext<'_>,
    ) -> Result<String, String> {
        let commit = self.context(context, "", random_uuid())?;
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            commit
                .bind_on(connection.as_mut().map_err(|_| unavailable())?, false)
                .await
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result);
        connection.release().await;
        result.map(|sid| sid.to_string())
    }

    pub(super) async fn prepare(
        &self,
        context: OidcSessionContext<'_>,
        client_id: &str,
    ) -> Result<OidcSessionGrantCommit, String> {
        if client_id.trim().is_empty() {
            return Err(unavailable());
        }
        let mut commit = self.context(context, client_id, random_uuid())?;
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),sqlx::query_as::<_,(Uuid,String,Vec<u8>,bool)>(
            "SELECT s.sid,s.user_id,s.auth_digest,s.logout_jti IS NULL FROM aegaeon.runtime_oidc_auth_bindings b JOIN aegaeon.runtime_oidc_sessions s ON (s.namespace,s.sid)=(b.namespace,b.sid) WHERE b.namespace=$1 AND b.auth_digest=$2")
            .bind(self.database.namespace.as_ref()).bind(commit.auth_digest.as_slice()).fetch_optional(connection.as_mut().map_err(|_|unavailable())?))
            .await.map_err(|_|unavailable()).and_then(|result|result.map_err(|_|unavailable()));
        connection.release().await;
        if let Some((sid, user, auth, active)) = result? {
            if user != commit.user_id || !crate::util::constant_time_eq(&auth, &commit.auth_digest)
            {
                return Err(unavailable());
            }
            if active {
                commit.sid = sid;
            }
        }
        Ok(OidcSessionGrantCommit::postgres(commit))
    }

    pub(super) async fn add_client(&self, sid: &str, client: &str) -> Result<bool, String> {
        let Ok(sid) = Uuid::parse_str(sid) else {
            return Ok(false);
        };
        if client.trim().is_empty() {
            return Err(unavailable());
        }
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            sqlx::query_scalar("SELECT aegaeon.add_runtime_oidc_client($1,$2,$3)")
                .bind(self.database.namespace.as_ref())
                .bind(sid)
                .bind(client)
                .fetch_one(connection.as_mut().map_err(|_| unavailable())?)
                .await
                .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result);
        connection.release().await;
        result
    }
}
