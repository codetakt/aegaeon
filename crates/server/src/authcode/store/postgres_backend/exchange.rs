use super::super::exchange_commit::{
    validate_exchange_commit, validate_exchange_subject, ExchangeCommitError as Error,
};
use super::*;

impl PostgresTokenStoreBackend {
    pub(in crate::authcode::store) async fn remint(
        &self,
        access: AccessToken,
        meta: BearerTokenMeta,
    ) -> Result<String, String> {
        token_consistency::bearer_metadata_matches_access_token(&access, &meta)
            .map_err(str::to_string)?;
        let parent = meta.refresh_parent.as_deref().ok_or_else(unavailable)?;
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            let mut tx = connection.begin().await.map_err(|_| unavailable())?;
            let observed = self
                .lock_capability(&mut tx, parent)
                .await?
                .ok_or_else(unavailable)?;
            let current = observed.current_refresh(parent)?.ok_or_else(unavailable)?;
            let (_, now) = clock(&mut tx).await?;
            token_consistency::refresh_parent_matches_remint(&current, &access, &meta, now)
                .map_err(str::to_string)?;
            token_consistency::refresh_token_covers_access_token(&current, &access, &meta)
                .map_err(str::to_string)?;
            self.extend_family(&mut tx, &access, &meta, None).await?;
            self.insert_access(&mut tx, &access, &meta, observed.row.subject_generation)
                .await?;
            self.check_descendant(&mut tx, &access, &meta, Some(&current))
                .await?;
            tx.commit().await.map_err(|_| unavailable())?;
            Ok(access.token.clone())
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|r| r);
        connection.release().await;
        result
    }

    pub(in crate::authcode::store) async fn exchange(
        &self,
        access: AccessToken,
        output: BearerTokenMeta,
        expected: BearerTokenMeta,
    ) -> Result<String, Error> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| Error::Storage(unavailable()))?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            let mut tx = connection.begin().await.map_err(|_| unavailable())?;
            let first = self
                .load_on(&mut tx, &expected.token_id, false)
                .await?
                .ok_or("exchange subject missing")?;
            let generation = self
                .lock_subject(&mut tx, &first.row.subject_digest, false)
                .await?
                .ok_or("exchange subject authority missing")?;
            self.lock_lineage(&mut tx, &first.row).await?;
            // Refresh precedes access in the lock order. It must have the already locked lineage.
            let parent = if let Some(parent) = output.refresh_parent.as_deref() {
                let first_parent = self
                    .load_on(&mut tx, parent, false)
                    .await?
                    .ok_or("exchange parent missing")?;
                if first_parent.row.family_id != first.row.family_id
                    || first_parent.row.root_id != first.row.root_id
                    || first_parent.row.subject_digest != first.row.subject_digest
                    || first_parent.row.subject_generation != generation
                {
                    return Err(Error::from("exchange parent lineage differs"));
                }
                let row = self
                    .load_on(&mut tx, parent, true)
                    .await?
                    .ok_or("exchange parent missing")?;
                if row.row.family_id != first.row.family_id
                    || row.row.root_id != first.row.root_id
                    || row.row.subject_digest != first.row.subject_digest
                    || row.row.subject_generation != generation
                {
                    return Err(Error::from("exchange parent lineage changed"));
                }
                Some(
                    row.current_refresh(parent)?
                        .ok_or("exchange parent inactive")?,
                )
            } else {
                None
            };
            let current = self
                .load_on(&mut tx, &expected.token_id, true)
                .await?
                .ok_or("exchange subject missing")?;
            if current.row.family_id != first.row.family_id
                || current.row.root_id != first.row.root_id
                || current.row.subject_digest != first.row.subject_digest
                || current.row.subject_generation != generation
            {
                return Err(Error::from("exchange subject lineage changed"));
            }
            let (subject_access, subject) = current
                .active_access(&expected.token_id)?
                .ok_or("exchange subject inactive")?;
            validate_exchange_subject(&subject_access, &subject)?;
            if serde_json::to_value(&subject).map_err(|_| unavailable())?
                != serde_json::to_value(&expected).map_err(|_| unavailable())?
            {
                return Err(Error::from("exchange subject changed"));
            }
            let (_, now) = clock(&mut tx).await?;
            validate_exchange_commit(&access, &output, &subject, parent.as_ref(), now)?;
            self.extend_family(&mut tx, &access, &output, None).await?;
            self.insert_access(&mut tx, &access, &output, generation)
                .await?;
            self.check_descendant(&mut tx, &access, &output, parent.as_ref())
                .await?;
            if self
                .load_on(&mut tx, &subject.token_id, false)
                .await?
                .ok_or("exchange subject missing")?
                .active_access(&subject.token_id)?
                .is_none()
            {
                return Err(Error::from("exchange subject expired"));
            }
            tx.commit().await.map_err(|_| unavailable())?;
            Ok(access.token.clone())
        })
        .await
        .map_err(|_| Error::Storage(unavailable()))
        .and_then(|r| r);
        connection.release().await;
        result
    }

    async fn check_descendant(
        &self,
        connection: &mut PgConnection,
        access: &AccessToken,
        meta: &BearerTokenMeta,
        parent: Option<&RefreshToken>,
    ) -> Result<(), String> {
        let (now, _) = clock(connection).await?;
        if now >= micros(meta.expires_at)?
            || parent
                .map(|p| micros(p.expires_at))
                .transpose()?
                .is_some_and(|expiry| now >= expiry)
            || self
                .load_on(connection, &access.token, false)
                .await?
                .ok_or_else(unavailable)?
                .active_access(&access.token)?
                .is_none()
        {
            return Err("descendant grant expired or inactive".into());
        }
        Ok(())
    }
}
