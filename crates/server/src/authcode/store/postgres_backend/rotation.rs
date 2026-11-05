use super::super::RefreshRotationError as Error;
use super::*;

fn failure(_: String) -> Error {
    Error::BackendUnavailable
}

impl PostgresTokenStoreBackend {
    async fn rotation_parent(
        &self,
        connection: &mut PgConnection,
        requested: &str,
    ) -> Result<Result<RefreshToken, Error>, String> {
        let Some(row) = self.lock_capability(connection, requested).await? else {
            return Ok(Err(Error::Invalid));
        };
        let Some(parent) = row.current_refresh(requested)? else {
            return Ok(Err(Error::Invalid));
        };
        if parent.rotated {
            self.revoke_family(
                connection,
                &parent.refresh_grant.as_ref().ok_or_else(unavailable)?.id,
            )
            .await?;
            return Ok(Err(Error::Reused));
        }
        if row.now_us >= row.row.expires_us {
            return Ok(Err(Error::Expired));
        }
        Ok(Ok(parent))
    }

    pub(in crate::authcode::store) async fn prepare_rotation(
        &self,
        requested: &str,
    ) -> Result<RefreshToken, Error> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| Error::BackendUnavailable)?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            let mut tx = connection
                .as_mut()
                .map_err(|_| unavailable())?
                .begin()
                .await
                .map_err(|_| unavailable())?;
            let parent = self.rotation_parent(&mut tx, requested).await?;
            // A confirmed reused-parent denial must survive the error response.
            tx.commit().await.map_err(|_| unavailable())?;
            Ok::<_, String>(parent)
        })
        .await
        .map_err(|_| Error::BackendUnavailable)
        .and_then(|r| r.map_err(failure))
        .and_then(|r| r);
        connection.release().await;
        result
    }

    pub(in crate::authcode::store) async fn rotate(
        &self,
        requested: &str,
        access: AccessToken,
        refresh: RefreshToken,
        meta: BearerTokenMeta,
    ) -> Result<(String, String), Error> {
        token_consistency::bearer_metadata_matches_access_token(&access, &meta)
            .map_err(|_| Error::InconsistentGrant)?;
        token_consistency::refresh_token_covers_access_token(&refresh, &access, &meta)
            .map_err(|_| Error::InconsistentGrant)?;
        if meta.refresh_parent.as_deref() != Some(refresh.token.as_str()) {
            return Err(Error::InconsistentGrant);
        }
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| Error::BackendUnavailable)?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_|unavailable())?;
            let mut tx=connection.as_mut().map_err(|_|unavailable())?.begin().await.map_err(|_|unavailable())?;
            let mut parent=match self.rotation_parent(&mut tx,requested).await? {
                Ok(parent)=>parent,Err(error)=>{tx.commit().await.map_err(|_|unavailable())?;return Ok(Err(error));}
            };
            if !valid_successor(&parent,&refresh)? {return Ok(Err(Error::InconsistentGrant));}
            let generation=self.lock_subject(&mut tx,&sha256_digest(parent.user_id.as_bytes()),false).await?.ok_or_else(unavailable)?;
            self.extend_family(&mut tx,&access,&meta,Some(&refresh)).await?;
            parent.rotated=true;
            sqlx::query("UPDATE aegaeon.runtime_token_capabilities SET rotated=true,payload=$3 WHERE namespace=$1 AND token_digest=$2")
                .bind(self.database.namespace.as_ref()).bind(sha256_digest(requested.as_bytes()).as_slice()).bind(encode(&parent)?).execute(&mut *tx).await.map_err(|_|unavailable())?;
            self.insert_refresh(&mut tx,&refresh,generation).await?;self.insert_access(&mut tx,&access,&meta,generation).await?;
            let (now,_)=clock(&mut tx).await?;
            let current=self.load_on(&mut tx,&refresh.token,false).await?.ok_or_else(unavailable)?;
            if now>=micros(parent.expires_at)?||now>=micros(meta.expires_at)?||now>=micros(refresh.expires_at)?||current.current_refresh(&refresh.token)?.is_none() {return Ok(Err(Error::Expired));}
            // Access expiry is independently encoded and checked after all locks/writes.
            if self.load_on(&mut tx,&access.token,false).await?.ok_or_else(unavailable)?.active_access(&access.token)?.is_none() {return Ok(Err(Error::Expired));}
            tx.commit().await.map_err(|_|unavailable())?;Ok(Ok((access.token,refresh.token)))
        }).await.map_err(|_|Error::BackendUnavailable).and_then(|r:Result<_,String>|r.map_err(failure)).and_then(|r|r);
        connection.release().await;
        result
    }
}

fn valid_successor(parent: &RefreshToken, next: &RefreshToken) -> Result<bool, String> {
    let Some(count) = parent.rotation_count.checked_add(1) else {
        return Ok(false);
    };
    if parent.token == next.token
        || next.rotated
        || next.rotation_count != count
        || parent
            .sender_binding
            .as_ref()
            .is_some_and(|binding| next.sender_binding.as_ref() != Some(binding))
    {
        return Ok(false);
    }
    let mut expected = parent.clone();
    expected.token = next.token.clone();
    expected.rotation_count = count;
    expected.rotated = false;
    // Existing bearer refresh may acquire the validated sender binding at rotation.
    expected.sender_binding.clone_from(&next.sender_binding);
    Ok(serde_json::to_value(expected).map_err(|_| unavailable())?
        == serde_json::to_value(next).map_err(|_| unavailable())?)
}
