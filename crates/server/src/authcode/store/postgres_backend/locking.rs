use super::reads::Observed;
use super::records::Capability;
use super::*;

impl PostgresTokenStoreBackend {
    // Consistent order: exchange root, refresh family, refresh node, access node.
    // A read first discovers keys; the locked read must retain those exact keys.
    pub(super) async fn lock_lineage(
        &self,
        connection: &mut PgConnection,
        row: &Capability,
    ) -> Result<(), String> {
        if let Some(root) = &row.root_id {
            sqlx::query("SELECT id FROM aegaeon.runtime_exchange_roots WHERE namespace=$1 AND id=$2 FOR UPDATE")
                .bind(self.database.namespace.as_ref()).bind(root).fetch_optional(&mut *connection).await.map_err(|_|unavailable())?;
        }
        if let Some(family) = &row.family_id {
            sqlx::query("SELECT id FROM aegaeon.runtime_refresh_families WHERE namespace=$1 AND id=$2 FOR UPDATE")
                .bind(self.database.namespace.as_ref()).bind(family).fetch_optional(connection).await.map_err(|_|unavailable())?;
        }
        Ok(())
    }

    pub(super) async fn lock_capability(
        &self,
        connection: &mut PgConnection,
        requested: &str,
    ) -> Result<Option<Observed>, String> {
        let Some(first) = self.load_on(connection, requested, false).await? else {
            return Ok(None);
        };
        let Some(generation) = self
            .lock_subject(connection, &first.row.subject_digest, false)
            .await?
        else {
            return Ok(None);
        };
        self.lock_lineage(connection, &first.row).await?;
        let Some(current) = self.load_on(connection, requested, true).await? else {
            return Ok(None);
        };
        if current.row.subject_generation != generation {
            return Ok(None);
        }
        if current.row.subject_digest != first.row.subject_digest
            || current.row.family_id != first.row.family_id
            || current.row.root_id != first.row.root_id
        {
            return Err(unavailable());
        }
        Ok(Some(current))
    }

    pub(super) async fn revoke_family(
        &self,
        connection: &mut PgConnection,
        family: &str,
    ) -> Result<(), String> {
        sqlx::query(
            "UPDATE aegaeon.runtime_refresh_families SET revoked=true WHERE namespace=$1 AND id=$2",
        )
        .bind(self.database.namespace.as_ref())
        .bind(family)
        .execute(connection)
        .await
        .map_err(|_| unavailable())?;
        Ok(())
    }

    pub(super) async fn extend_family(
        &self,
        connection: &mut PgConnection,
        access: &AccessToken,
        meta: &BearerTokenMeta,
        refresh: Option<&RefreshToken>,
    ) -> Result<(), String> {
        let Some(reference) =
            super::super::refresh_grants::access_reference(access, meta).map_err(str::to_string)?
        else {
            return Ok(());
        };
        if refresh.is_some_and(|r| r.refresh_grant.as_ref() != Some(reference)) {
            return Err(unavailable());
        }
        let until = micros(
            super::super::refresh_grants::descendant_deadline(access, meta, refresh)
                .map_err(str::to_string)?,
        )?;
        let result=sqlx::query("UPDATE aegaeon.runtime_refresh_families SET expires_us=greatest(expires_us,$3) WHERE namespace=$1 AND id=$2 AND NOT revoked AND version=1 AND client_digest=$4 AND subject_digest=$5 AND expires_us>floor(extract(epoch from clock_timestamp())*1000000)::bigint")
            .bind(self.database.namespace.as_ref()).bind(&reference.id).bind(until).bind(sha256_digest(access.client_id.as_bytes()).as_slice()).bind(sha256_digest(access.user_id.as_bytes()).as_slice())
            .execute(connection).await.map_err(|_|unavailable())?;
        if result.rows_affected() != 1 {
            return Err("refresh family is inactive".into());
        }
        Ok(())
    }
}
