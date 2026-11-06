use super::super::RetainedRoot;
use super::*;

impl PostgresTokenStoreBackend {
    pub(in crate::authcode::store) async fn retained_deadline(
        &self,
        retained: &RetainedRoot,
    ) -> Result<Option<SystemTime>, String> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            self.retained_deadline_on(
                connection.as_mut().map_err(|_| unavailable())?,
                retained,
                false,
            ),
        )
        .await
        .map_err(|_| unavailable())
        .and_then(|r| r);
        connection.release().await;
        result
    }

    // With lock=true this reuses the caller's open SQL transaction and holds the
    // subject/root/family authority through its commit; it never acquires a pool slot.
    pub(in crate::authcode::store) async fn retained_deadline_on(
        &self,
        connection: &mut PgConnection,
        retained: &RetainedRoot,
        lock: bool,
    ) -> Result<Option<SystemTime>, String> {
        if retained.client.is_empty()
            || retained.subject.is_empty()
            || retained
                .refresh_grant
                .as_ref()
                .is_some_and(|r| !r.supported())
            || super::records::validate_root(&retained.root).is_err()
        {
            return Ok(None);
        }
        let subject = sha256_digest(retained.subject.as_bytes());
        if lock {
            if self
                .lock_subject(connection, &subject, false)
                .await?
                .is_none()
            {
                return Ok(None);
            }
            sqlx::query("SELECT id FROM aegaeon.runtime_exchange_roots WHERE namespace=$1 AND id=$2 FOR SHARE")
                .bind(self.database.namespace.as_ref()).bind(&retained.root.id).fetch_optional(&mut *connection).await.map_err(|_|unavailable())?;
            if let Some(family) = &retained.refresh_grant {
                sqlx::query("SELECT id FROM aegaeon.runtime_refresh_families WHERE namespace=$1 AND id=$2 FOR SHARE")
                    .bind(self.database.namespace.as_ref()).bind(&family.id).fetch_optional(&mut *connection).await.map_err(|_|unavailable())?;
            }
        }
        let row=sqlx::query_as::<_,(i64,Option<i64>)>("SELECT r.expires_us,f.expires_us FROM aegaeon.runtime_exchange_roots r JOIN aegaeon.runtime_token_subjects s ON (s.namespace,s.subject_digest)=(r.namespace,r.subject_digest) LEFT JOIN aegaeon.runtime_refresh_families f ON (f.namespace,f.id)=(r.namespace,r.family_id) WHERE r.namespace=$1 AND r.id=$2 AND r.client_digest=$3 AND r.subject_digest=$4 AND NOT r.revoked AND r.subject_generation=s.generation AND r.family_id IS NOT DISTINCT FROM $5 AND (r.family_id IS NULL OR (f.version=1 AND NOT f.revoked AND f.client_digest=r.client_digest AND f.subject_digest=r.subject_digest AND f.subject_generation=r.subject_generation))")
            .bind(self.database.namespace.as_ref()).bind(&retained.root.id).bind(sha256_digest(retained.client.as_bytes()).as_slice()).bind(subject.as_slice())
            .bind(retained.refresh_grant.as_ref().map(|r|r.id.as_str())).fetch_optional(&mut *connection).await.map_err(|_|unavailable())?;
        let Some((root_end, family_end)) = row else {
            return Ok(None);
        };
        let end = family_end.map_or(root_end, |end| end.min(root_end));
        let (now, _) = clock(connection).await?;
        if root_end != micros(retained.root.expires_at)? || end <= now {
            return Ok(None);
        }
        Ok(UNIX_EPOCH.checked_add(Duration::from_micros(
            u64::try_from(end).map_err(|_| unavailable())?,
        )))
    }
}
