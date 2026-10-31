use super::{Error, Result, DEADLINE};
use sqlx::{Connection, PgConnection};

/// Constructed only from a live connection. It has no authority semantics.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PostgresObservation {
    cluster_id: i64,
    database_oid: i64,
    database_name: String,
    started_us: i64,
    timeline: u32,
    wal_position: u64,
}
impl PostgresObservation {
    /// Exact store incarnation and a nondecreasing observation of WAL. This
    /// cannot detect all logical restores or rollback of the observer itself.
    pub fn follows(&self, previous: &Self) -> bool {
        self.cluster_id == previous.cluster_id
            && self.database_oid == previous.database_oid
            && self.database_name == previous.database_name
            && self.started_us == previous.started_us
            && self.timeline == previous.timeline
            && self.wal_position >= previous.wal_position
    }

    /// A necessary separation check, not independent durability qualification.
    pub fn different_cluster(&self, other: &Self) -> bool {
        self.cluster_id != other.cluster_id
    }
}

/// Own the authenticated connection through observation and failure cleanup.
/// The caller supplies transport/authentication and exclusive connection custody.
pub struct Postgres {
    connection: Option<PgConnection>,
    observed: PostgresObservation,
}
impl Postgres {
    pub async fn observe(mut connection: PgConnection) -> Result<Self> {
        let observed = tokio::time::timeout(DEADLINE, read(&mut connection))
            .await
            .map_err(|_| Error::Deadline)??;
        Ok(Self {
            connection: Some(connection),
            observed,
        })
    }
    pub fn observation(&self) -> &PostgresObservation {
        &self.observed
    }
    /// Any failure discards this link; no reconnect, retry or last-known allow.
    pub async fn recheck(&mut self, expected: &PostgresObservation) -> Result<()> {
        let mut connection = self.connection.take().ok_or(Error::Refused)?;
        let current = tokio::time::timeout(DEADLINE, read(&mut connection))
            .await
            .map_err(|_| Error::Deadline)??;
        if !current.follows(expected) || !current.follows(&self.observed) {
            return Err(Error::Refused);
        }
        self.observed = current;
        self.connection = Some(connection);
        Ok(())
    }
    pub async fn close(mut self) -> Result<()> {
        if let Some(connection) = self.connection.take() {
            tokio::time::timeout(DEADLINE, connection.close())
                .await
                .map_err(|_| Error::Deadline)??;
        }
        Ok(())
    }
}

async fn read(connection: &mut PgConnection) -> Result<PostgresObservation> {
    let row: (i64, i64, String, i64, String, String, bool) = sqlx::query_as(
        "SELECT c.system_identifier,d.oid::bigint,d.datname::text, \
         (extract(epoch FROM pg_catalog.pg_postmaster_start_time())*1000000)::bigint, \
         pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn()), \
         pg_catalog.pg_current_wal_lsn()::text, \
         pg_catalog.current_setting('server_version_num')::integer BETWEEN 180000 AND 189999 \
         AND NOT pg_catalog.pg_is_in_recovery() \
         AND pg_catalog.current_setting('fsync')='on' \
         AND pg_catalog.current_setting('full_page_writes')='on' \
         AND pg_catalog.current_setting('synchronous_commit')='on' \
         AND pg_catalog.current_setting('transaction_read_only')='off' \
         FROM pg_catalog.pg_control_system() c, pg_catalog.pg_database d \
         WHERE d.datname=pg_catalog.current_database()",
    )
    .fetch_one(connection)
    .await?;
    if !row.6
        || row.0 == 0
        || !(1..=i64::from(u32::MAX)).contains(&row.1)
        || row.2.is_empty()
        || row.2.len() > 63
        || row.3 <= 0
        || row.4.len() != 24
        || !row.4.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::Refused);
    }
    let timeline = u32::from_str_radix(&row.4[..8], 16).map_err(|_| Error::Refused)?;
    if timeline == 0 {
        return Err(Error::Refused);
    }
    Ok(PostgresObservation {
        cluster_id: row.0,
        database_oid: row.1,
        database_name: row.2,
        started_us: row.3,
        timeline,
        wal_position: position(&row.5)?,
    })
}

fn position(value: &str) -> Result<u64> {
    let (high, low) = value.split_once('/').ok_or(Error::Refused)?;
    let word = |part: &str| -> Result<u32> {
        if part.is_empty() || part.len() > 8 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Refused);
        }
        u32::from_str_radix(part, 16).map_err(|_| Error::Refused)
    };
    Ok((u64::from(word(high)?) << 32) | u64::from(word(low)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn store_observation_wal_parser_retains_full_unsigned_domain() {
        assert_eq!(position("FFFFFFFF/FFFFFFFF").unwrap(), u64::MAX);
        assert_eq!(position("1/0").unwrap(), 1_u64 << 32);
        assert_eq!(position("0/0").unwrap(), 0);
        for value in ["/0", "0/", "0/0/0", "100000000/0", "-1/0", "0/+1", " 0/0"] {
            assert!(position(value).is_err(), "{value}");
        }
    }
}
