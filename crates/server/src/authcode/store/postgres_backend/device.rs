use super::{records::InitialGrant, *};
impl PostgresTokenStoreBackend {
    pub(in crate::authcode::store) async fn redeem_device(
        &self,
        access: AccessToken,
        meta: BearerTokenMeta,
        commit: crate::device_authz::PostgresDeviceGrantCommit,
    ) -> Result<String, String> {
        if !self.database.same_database(&commit.database) || !commit.matches(&access, &meta) {
            return Err(unavailable());
        }
        let grant = InitialGrant::new(access, None, meta)?;
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            let mut tx = connection
                .as_mut()
                .map_err(|_| unavailable())?
                .begin()
                .await
                .map_err(|_| unavailable())?;
            commit.lock_on(&mut tx).await?;
            self.publish_initial(&mut tx, &grant).await?;
            self.check_initial_deadline(&mut tx, &grant).await?;
            commit.consume_on(&mut tx).await?;
            tx.commit().await.map_err(|_| unavailable())?;
            Ok(grant.access.token.clone())
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|r| r);
        connection.release().await;
        result
    }
}
