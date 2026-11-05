use super::records::Capability;
use super::*;

pub(super) struct Observed {
    pub row: Capability,
    pub now_us: i64,
    pub family_active: bool,
    pub subject_active: bool,
    pub family_expires: Option<i64>,
    pub root_active: bool,
    pub root_expires: Option<i64>,
}

pub(super) fn observation_query(relation: &str) -> String {
    format!("SELECT c.*,floor(extract(epoch from clock_timestamp())*1000000)::bigint AS now_us, coalesce(s.generation=c.subject_generation,false) AS subject_active,
    CASE WHEN c.family_id IS NULL THEN true ELSE coalesce(NOT f.revoked AND f.version=1 AND f.client_digest=c.client_digest AND f.subject_digest=c.subject_digest AND f.subject_generation=c.subject_generation,false) END AS family_active,f.expires_us AS family_expires,
    CASE WHEN c.root_id IS NULL THEN true ELSE coalesce(NOT r.revoked AND r.client_digest=c.client_digest AND r.subject_digest=c.subject_digest AND r.subject_generation=c.subject_generation AND r.family_id IS NOT DISTINCT FROM c.family_id,false) END AS root_active,r.expires_us AS root_expires
 FROM {relation} c
    LEFT JOIN aegaeon.runtime_token_subjects s ON (s.namespace,s.subject_digest)=(c.namespace,c.subject_digest)
    LEFT JOIN aegaeon.runtime_refresh_families f ON (f.namespace,f.id)=(c.namespace,c.family_id)
    LEFT JOIN aegaeon.runtime_exchange_roots r ON (r.namespace,r.id)=(c.namespace,c.root_id)
")
}

fn read_query() -> String {
    format!(
        "{} WHERE c.namespace=$1 AND c.token_digest=$2",
        observation_query("aegaeon.runtime_token_capabilities")
    )
}

impl Observed {
    fn authority(
        &self,
        deadline: SystemTime,
        root: Option<&crate::policy::token_exchange::ExchangeRoot>,
    ) -> Result<bool, String> {
        let family = self.row.family_id.is_none()
            || self.family_expires.is_some_and(|expires| {
                expires > self.now_us && micros(deadline).is_ok_and(|end| expires >= end)
            });
        let root = match root {
            None => self.row.root_id.is_none(),
            Some(root) => {
                self.root_expires == Some(micros(root.expires_at)?)
                    && self
                        .root_expires
                        .is_some_and(|expires| expires > self.now_us)
            }
        };
        Ok(!self.row.revoked
            && self.subject_active
            && self.family_active
            && family
            && self.root_active
            && root)
    }

    pub(super) fn active_access(
        &self,
        requested: &str,
    ) -> Result<Option<(AccessToken, BearerTokenMeta)>, String> {
        if self.row.kind != 1 {
            return Ok(None);
        }
        let (access, meta) = self.row.access(requested)?;
        let deadline = super::super::refresh_grants::descendant_deadline(&access, &meta, None)
            .map_err(str::to_string)?;
        if self.row.expires_us <= self.now_us
            || !self.authority(deadline, access.exchange_root.as_ref())?
        {
            return Ok(None);
        }
        Ok(Some((access, meta)))
    }

    pub(super) fn current_refresh(&self, requested: &str) -> Result<Option<RefreshToken>, String> {
        if self.row.kind != 2 {
            return Ok(None);
        }
        let token = self.row.refresh(requested)?;
        if !self.authority(
            token.expires_at,
            token.exchange_grant.as_ref().and_then(|g| g.root()),
        )? {
            return Ok(None);
        }
        Ok(Some(token))
    }
}

impl PostgresTokenStoreBackend {
    pub(super) async fn load_on(
        &self,
        connection: &mut PgConnection,
        requested: &str,
        lock: bool,
    ) -> Result<Option<Observed>, String> {
        let query = if lock {
            format!("{} FOR UPDATE OF c", read_query())
        } else {
            read_query()
        };
        let mut row = sqlx::query_as::<_, Observed>(&query)
            .bind(self.database.namespace.as_ref())
            .bind(sha256_digest(requested.as_bytes()).as_slice())
            .fetch_optional(&mut *connection)
            .await
            .map_err(|_| unavailable())?;
        if lock {
            if let Some(row) = &mut row {
                row.now_us = clock(connection).await?.0;
            }
        }
        Ok(row)
    }

    pub(super) async fn load(&self, requested: &str) -> Result<Option<Observed>, String> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            sqlx::query_as::<_, Observed>(&read_query())
                .bind(self.database.namespace.as_ref())
                .bind(sha256_digest(requested.as_bytes()).as_slice())
                .fetch_optional(connection.as_mut().map_err(|_| unavailable())?),
        )
        .await
        .map_err(|_| unavailable())
        .and_then(|r| r.map_err(|_| unavailable()));
        connection.release().await;
        result
    }

    pub(in crate::authcode::store) async fn access(
        &self,
        requested: &str,
    ) -> Result<Option<(AccessToken, BearerTokenMeta)>, String> {
        self.load(requested)
            .await?
            .map(|row| row.active_access(requested))
            .transpose()
            .map(Option::flatten)
    }

    pub(in crate::authcode::store) async fn refresh(
        &self,
        requested: &str,
    ) -> Result<Option<RefreshToken>, String> {
        self.load(requested)
            .await?
            .map(|row| row.current_refresh(requested))
            .transpose()
            .map(Option::flatten)
    }

    pub(in crate::authcode::store) async fn observe_access(
        &self,
        requested: &str,
    ) -> Result<Option<AccessToken>, String> {
        self.load(requested)
            .await?
            .filter(|row| row.row.kind == 1)
            .map(|row| row.row.access(requested).map(|(access, _)| access))
            .transpose()
    }
}

impl sqlx::FromRow<'_, sqlx::postgres::PgRow> for Observed {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            row: Capability::from_row(row)?,
            now_us: row.try_get("now_us")?,
            family_active: row.try_get("family_active")?,
            subject_active: row.try_get("subject_active")?,
            family_expires: row.try_get("family_expires")?,
            root_active: row.try_get("root_active")?,
            root_expires: row.try_get("root_expires")?,
        })
    }
}
