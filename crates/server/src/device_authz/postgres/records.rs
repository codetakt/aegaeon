use super::*;
use crate::authcode::types::{AccessToken, BearerTokenMeta};
#[derive(Clone)]
pub(super) struct Record {
    pub device_digest: Vec<u8>,
    pub client_id: String,
    pub scope: Option<String>,
    pub resource: Option<String>,
    pub environment_id: Option<String>,
    pub status: i16,
    pub subject: Option<String>,
    pub expires_us: i64,
    pub last_poll_us: Option<i64>,
    pub interval_secs: i64,
}
impl sqlx::FromRow<'_, sqlx::postgres::PgRow> for Record {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            device_digest: row.try_get("device_digest")?,
            client_id: row.try_get("client_id")?,
            scope: row.try_get("scope")?,
            resource: row.try_get("resource")?,
            environment_id: row.try_get("environment_id")?,
            status: row.try_get("status")?,
            subject: row.try_get("subject")?,
            expires_us: row.try_get("expires_us")?,
            last_poll_us: row.try_get("last_poll_us")?,
            interval_secs: row.try_get("interval_secs")?,
        })
    }
}
/// An approved current-row observation, usable only by the matching SQL grant store.
/// Polling does not consume this approval. Only a confirmed token transaction does.
#[derive(Clone)]
pub(crate) struct PostgresDeviceGrantCommit {
    pub(crate) database: PostgresGrantDatabase,
    pub(super) expected: Record,
    pub(super) audience: String,
}
impl PostgresDeviceGrantCommit {
    pub(crate) fn matches(&self, access: &AccessToken, meta: &BearerTokenMeta) -> bool {
        access.client_id == self.expected.client_id
            && Some(&access.user_id) == self.expected.subject.as_ref()
            && access.scope == self.expected.scope
            && meta.audience == self.audience
            && access.refresh_grant.is_none()
            && meta.refresh_parent.is_none()
    }
    pub(crate) async fn lock_on(&self, conn: &mut PgConnection) -> Result<(), String> {
        let observed=sqlx::query_as::<_,Record>("SELECT * FROM aegaeon.runtime_device_codes WHERE namespace=$1 AND device_digest=$2 FOR UPDATE")
            .bind(self.database.namespace.as_ref()).bind(&self.expected.device_digest).fetch_optional(&mut *conn).await.map_err(|_|unavailable())?.ok_or_else(unavailable)?;
        let expected = &self.expected;
        if observed.status != 1
            || observed.client_id != expected.client_id
            || observed.subject != expected.subject
            || observed.scope != expected.scope
            || observed.resource != expected.resource
            || observed.environment_id != expected.environment_id
            || observed.expires_us != expected.expires_us
            || clock(conn).await? >= observed.expires_us
        {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(crate) async fn consume_on(&self, conn: &mut PgConnection) -> Result<(), String> {
        if clock(conn).await? >= self.expected.expires_us {
            return Err(unavailable());
        }
        let deleted=sqlx::query("DELETE FROM aegaeon.runtime_device_codes WHERE namespace=$1 AND device_digest=$2 AND status=1")
            .bind(self.database.namespace.as_ref()).bind(&self.expected.device_digest).execute(conn).await.map_err(|_|unavailable())?.rows_affected();
        if deleted != 1 {
            return Err(unavailable());
        }
        Ok(())
    }
}
