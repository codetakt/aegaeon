use super::*;
#[derive(Debug, PartialEq, Eq)]
pub(in crate::client_registry) enum Completion {
    Admitted,
    Failed,
    ChangedKey,
    Capacity,
}
impl PostgresJwksState {
    pub(in crate::client_registry) async fn finish(
        &self,
        permit: &FetchPermit,
        incoming: Option<&AdmittedKeys>,
    ) -> Result<Completion, String> {
        if !Arc::ptr_eq(&self.identity, &permit.identity) || permit.remaining().is_none() {
            return Err(unavailable());
        }
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_|unavailable())?;
            let mut tx=connection.begin().await.map_err(|_|unavailable())?;
            let mut row=sqlx::query_as::<_,Row>("SELECT * FROM aegaeon.runtime_jwks_fetches WHERE namespace=$1 AND uri_digest=$2 FOR UPDATE")
                .bind(self.namespace.as_ref()).bind(permit.uri.as_slice()).fetch_optional(&mut *tx).await.map_err(|_|unavailable())?.ok_or_else(unavailable)?;
            let now=clock(&mut tx).await?;
            if row.owner!=Some(permit.owner)||row.lease_until.is_none_or(|until|now>=until)||now>=row.expires||permit.remaining().is_none(){return Err(unavailable());}
            let lease_until=row.lease_until.ok_or_else(unavailable)?;
            let outcome=match incoming {
                None=>Completion::Failed,
                Some(incoming)=>self.bind(&mut tx,permit,now,incoming).await?,
            };
            if outcome==Completion::Admitted {row.failures=0;row.open_until=None;row.owner=None;row.lease_until=None;}
            else {failure(&mut row,now,permit.threshold,permit.reset_us)?;}
            row.expires=horizon(now,permit.ttl_us)?;
            save(&mut tx,&self.namespace,&permit.uri,&row).await?;
            if clock(&mut tx).await?>=lease_until || permit.remaining().is_none(){return Err(unavailable());}
            tx.commit().await.map_err(|_|unavailable())?;
            if permit.remaining().is_none(){return Err(unavailable());}
            Ok(outcome)
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }
    async fn bind(
        &self,
        conn: &mut PgConnection,
        permit: &FetchPermit,
        now: i64,
        incoming: &AdmittedKeys,
    ) -> Result<Completion, String> {
        let stored=sqlx::query_as::<_,(String,i64)>("SELECT bindings,expires_us FROM aegaeon.runtime_jwks_bindings WHERE namespace=$1 AND uri_digest=$2 FOR UPDATE")
            .bind(self.namespace.as_ref()).bind(permit.uri.as_slice()).fetch_optional(&mut *conn).await.map_err(|_|unavailable())?;
        let mut bindings = match stored {
            Some((raw, expiry)) if expiry > now => {
                serde_json::from_str::<HashMap<String, String>>(&raw).map_err(|_| unavailable())?
            }
            _ => HashMap::new(),
        };
        if !permit.allow_reuse
            && incoming
                .fingerprints
                .iter()
                .any(|(kid, value)| bindings.get(kid).is_some_and(|old| old != value))
        {
            return Ok(Completion::ChangedKey);
        }
        bindings.extend(
            incoming
                .fingerprints
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        let Some(encoded) = bounded_json(&bindings) else {
            return Ok(Completion::Capacity);
        };
        sqlx::query("INSERT INTO aegaeon.runtime_jwks_bindings(namespace,uri_digest,bindings,expires_us,body_digest,admission_expires_us) VALUES($1,$2,$3,$4,$5,$4) ON CONFLICT(namespace,uri_digest) DO UPDATE SET bindings=EXCLUDED.bindings,expires_us=EXCLUDED.expires_us,body_digest=EXCLUDED.body_digest,admission_expires_us=EXCLUDED.admission_expires_us")
            .bind(self.namespace.as_ref()).bind(permit.uri.as_slice()).bind(encoded).bind(horizon(now,permit.ttl_us)?).bind(incoming.body_digest.as_slice()).execute(conn).await.map_err(|_|unavailable())?;
        Ok(Completion::Admitted)
    }
}

fn bounded_json(map: &HashMap<String, String>) -> Option<String> {
    struct Limited(Vec<u8>);
    impl std::io::Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > MAX_BINDING_BYTES {
                return Err(std::io::Error::other("JWKS binding capacity"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Limited(Vec::new());
    serde_json::to_writer(&mut output, map).ok()?;
    String::from_utf8(output.0).ok()
}
