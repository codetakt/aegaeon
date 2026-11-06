use super::*;

type EventRow = (Uuid, String, Uuid, Vec<String>);
fn event(row: EventRow) -> OidcLogoutEvent {
    OidcLogoutEvent {
        sid: row.0.to_string(),
        user_id: row.1,
        jti: row.2.to_string(),
        client_ids: row.3,
    }
}

impl PostgresOidcSessionBackend {
    pub(in crate::oidc::session::imp) async fn logout_sid(
        &self,
        sid: &str,
        ttl: u64,
    ) -> Result<Option<OidcLogoutEvent>, String> {
        let Ok(sid) = Uuid::parse_str(sid) else {
            return Ok(None);
        };
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            sqlx::query_as::<_, EventRow>(
                "SELECT * FROM aegaeon.logout_runtime_oidc_session($1,$2,$3,$4)",
            )
            .bind(self.database.namespace.as_ref())
            .bind(sid)
            .bind(random_uuid())
            .bind(i64::try_from(ttl).map_err(|_| unavailable())?)
            .fetch_optional(connection.as_mut().map_err(|_| unavailable())?)
            .await
            .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result);
        connection.release().await;
        result.map(|row| row.map(event))
    }

    pub(in crate::oidc::session::imp) async fn logout_auth_session(
        &self,
        auth_session: &str,
        ttl: u64,
    ) -> Result<Option<OidcLogoutEvent>, String> {
        let digest = sha256_digest(auth_session.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            sqlx::query_as::<_, EventRow>(
                "SELECT * FROM aegaeon.logout_runtime_oidc_auth_session($1,$2,$3,$4)",
            )
            .bind(self.database.namespace.as_ref())
            .bind(digest.as_slice())
            .bind(random_uuid())
            .bind(i64::try_from(ttl).map_err(|_| unavailable())?)
            .fetch_optional(connection.as_mut().map_err(|_| unavailable())?)
            .await
            .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result);
        connection.release().await;
        result.map(|row| row.map(event))
    }

    pub(in crate::oidc::session::imp) async fn logout_user(
        &self,
        user: &str,
        ttl: u64,
    ) -> Result<Vec<OidcLogoutEvent>, String> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            sqlx::query_as::<_, EventRow>(
                "SELECT * FROM aegaeon.logout_runtime_oidc_user($1,$2,$3)",
            )
            .bind(self.database.namespace.as_ref())
            .bind(user)
            .bind(i64::try_from(ttl).map_err(|_| unavailable())?)
            .fetch_all(connection.as_mut().map_err(|_| unavailable())?)
            .await
            .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result);
        connection.release().await;
        result.map(|rows| rows.into_iter().map(event).collect())
    }
}
