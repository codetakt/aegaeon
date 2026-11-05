use super::*;
impl PostgresJwksState {
    pub(in crate::client_registry) async fn acquire(
        &self,
        uri: &str,
        policy: &JwksRuntimePolicy,
    ) -> Result<Option<FetchPermit>, String> {
        let anchor = Instant::now();
        let ttl_us = micros(
            super::super::RedisJwksRuntimeState::ttl_i64(policy)
                .map_err(|_| unavailable())?
                .try_into()
                .map_err(|_| unavailable())?,
        )?;
        let reset_us = micros(policy.circuit_reset_secs)?;
        if policy.circuit_open_fails == 0 {
            return Err(unavailable());
        }
        let uri = sha256_digest(uri.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_|unavailable())?;
            let mut tx=connection.begin().await.map_err(|_|unavailable())?;
            let before=clock(&mut tx).await?;
            sqlx::query("INSERT INTO aegaeon.runtime_jwks_fetches(namespace,uri_digest,expires_us) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
                .bind(self.namespace.as_ref()).bind(uri.as_slice()).bind(horizon(before,ttl_us)?).execute(&mut *tx).await.map_err(|_|unavailable())?;
            let mut row=sqlx::query_as::<_,Row>("SELECT * FROM aegaeon.runtime_jwks_fetches WHERE namespace=$1 AND uri_digest=$2 FOR UPDATE")
                .bind(self.namespace.as_ref()).bind(uri.as_slice()).fetch_one(&mut *tx).await.map_err(|_|unavailable())?;
            let now=clock(&mut tx).await?;
            if row.expires<=now {row=Row{failures:0,open_until:None,owner:None,lease_until:None,expires:horizon(now,ttl_us)?};}
            if row.owner.is_some() {
                if row.lease_until.is_none_or(|until|until>now){return Ok(None);}
                failure(&mut row,now,policy.circuit_open_fails,reset_us)?;
            }
            if row.open_until.is_some_and(|until|until>now) {
                row.expires=horizon(now,ttl_us)?;save(&mut tx,&self.namespace,&uri,&row).await?;
                tx.commit().await.map_err(|_|unavailable())?;return Ok(None);
            }
            let mut entropy=[0;16];aegaeon_crypto::rand::fill_random(&mut entropy).map_err(|_|unavailable())?;
            let owner=uuid::Builder::from_random_bytes(entropy).into_uuid();
            row.owner=Some(owner);row.lease_until=Some(horizon(now,micros(FETCH_LEASE_SECS)?)?);row.expires=horizon(now,ttl_us)?;
            save(&mut tx,&self.namespace,&uri,&row).await?;
            tx.commit().await.map_err(|_|unavailable())?;
            let permit=FetchPermit{identity:self.identity.clone(),uri,owner,deadline:anchor+Duration::from_secs(FETCH_LEASE_SECS),ttl_us,reset_us,threshold:policy.circuit_open_fails,allow_reuse:policy.allow_kid_reuse};
            if permit.remaining().is_none(){return Err(unavailable());}Ok(Some(permit))
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }
}
