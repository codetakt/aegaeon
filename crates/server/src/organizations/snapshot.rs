//! Bounded, consistent native snapshot reader. Live authorization belongs to
//! the consuming HTTP boundary and must not use this older MVCC transaction.
use super::{model::require, repository::RepositoryError, AuthorityError, Scope};
use crate::subject_ownership::history::HashChain;
use serde::Serialize;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

mod sections;
use sections::{OWNERS, SECTIONS};
pub mod cli;
pub mod custody;
pub mod input;
pub mod staging;

pub const MAX_ROW_BYTES: usize = 256 * 1024;
pub const MAX_SECTION_ROWS: u64 = 1_000_000;
pub const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const PAGE_ROWS: i64 = 10;
const MAX_KEY_BYTES: usize = 4096;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub record: &'static str,
    pub version: u32,
    pub snapshot_id: Uuid,
    pub scope: Scope,
    pub captured_at: String,
    pub credential_transfer: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SectionDigest {
    pub section: &'static str,
    pub count: u64,
    pub sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest<'a> {
    pub record: &'static str,
    pub version: u32,
    pub snapshot_id: Uuid,
    pub scope: Scope,
    pub sections: &'a [SectionDigest],
    pub content_bytes: u64,
}

pub struct Reader {
    header: Header,
    database_snapshot: String,
    section: usize,
    after: Option<String>,
    count: u64,
    digest: HashChain,
    completed: Vec<SectionDigest>,
    bytes: u64,
    failed: bool,
}

fn section_digest(name: &str) -> HashChain {
    HashChain::new(&format!("aegaeon-organizations-snapshot-v1:{name}"))
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    result
}

impl Reader {
    /// The caller must first authorize the exact scope on the live primary and
    /// own a separate fresh repeatable-read, read-only transaction. Every next
    /// page and terminal manifest require another live authorization check.
    pub async fn start(
        tx: &mut Transaction<'_, Postgres>,
        scope: Scope,
    ) -> Result<Self, RepositoryError> {
        scope.validate()?;
        let row = sqlx::query("SELECT current_setting('transaction_isolation') AS isolation,current_setting('transaction_read_only') AS read_only,to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS captured,CASE WHEN octet_length(pg_current_snapshot()::text)<=65536 THEN pg_current_snapshot()::text ELSE NULL END AS snapshot")
            .fetch_one(&mut **tx).await?;
        require(
            row.try_get::<String, _>("isolation")? == "repeatable read"
                && row.try_get::<String, _>("read_only")? == "on",
        )?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2)")
            .bind(scope.environment_id).bind(scope.domain_id).fetch_one(&mut **tx).await?;
        require(exists)?;
        let header = Header {
            record: "header",
            version: 1,
            snapshot_id: Uuid::new_v4(),
            scope,
            captured_at: row.try_get("captured")?,
            credential_transfer: false,
        };
        let mut value = Self {
            header,
            database_snapshot: row
                .try_get::<Option<String>, _>("snapshot")?
                .ok_or(AuthorityError::Exhausted)?,
            section: 0,
            after: None,
            count: 0,
            digest: section_digest(SECTIONS[0].name),
            completed: Vec::with_capacity(SECTIONS.len()),
            bytes: 0,
            failed: false,
        };
        value.bytes = value.header_line()?.len() as u64;
        Ok(value)
    }

    pub fn header_line(&self) -> Result<Vec<u8>, RepositoryError> {
        line(&self.header)
    }

    /// Each returned vector owns at most ten bounded rows. The caller checks
    /// current authorization before emitting it and supplies a progress deadline.
    pub async fn next(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<Option<Vec<Vec<u8>>>, RepositoryError> {
        require(!self.failed)?;
        let result = self.next_checked(tx).await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    async fn next_checked(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<Option<Vec<Vec<u8>>>, RepositoryError> {
        let current: Option<String> = sqlx::query_scalar("SELECT CASE WHEN octet_length(pg_current_snapshot()::text)<=65536 THEN pg_current_snapshot()::text ELSE NULL END")
            .fetch_one(&mut **tx)
            .await?;
        require(current.as_ref() == Some(&self.database_snapshot))?;
        if self.section == SECTIONS.len() {
            return Ok(None);
        }
        let section = &SECTIONS[self.section];
        let query = format!("{OWNERS} SELECT row_key,CASE WHEN octet_length(row_data)<=$4 THEN row_data ELSE NULL END AS row_data FROM ({}) rows WHERE ($3::text IS NULL OR row_key COLLATE \"C\">$3 COLLATE \"C\") ORDER BY row_key COLLATE \"C\" LIMIT $5",section.query);
        let rows = sqlx::query(&query)
            .bind(self.header.scope.environment_id)
            .bind(self.header.scope.domain_id)
            .bind(&self.after)
            .bind(MAX_ROW_BYTES as i32)
            .bind(PAGE_ROWS)
            .fetch_all(&mut **tx)
            .await?;
        if rows.is_empty() {
            self.completed.push(SectionDigest {
                section: section.name,
                count: self.count,
                sha256: hex_digest(&self.digest.finish().1),
            });
            self.section += 1;
            self.after = None;
            self.count = 0;
            if let Some(next) = SECTIONS.get(self.section) {
                self.digest = section_digest(next.name);
            }
            return Ok(Some(Vec::new()));
        }
        let mut output = Vec::with_capacity(rows.len());
        for row in rows {
            let key: String = row.try_get("row_key")?;
            let data: Option<String> = row.try_get("row_data")?;
            let data = data.ok_or(RepositoryError::Unavailable)?;
            require(
                key.len() <= MAX_KEY_BYTES && self.after.as_ref().is_none_or(|prior| prior < &key),
            )?;
            let bytes = self.push(section.name, &key, &data)?;
            self.after = Some(key);
            output.push(bytes);
        }
        Ok(Some(output))
    }

    fn push(&mut self, section: &str, key: &str, data: &str) -> Result<Vec<u8>, RepositoryError> {
        let count = self
            .count
            .checked_add(1)
            .filter(|count| *count <= MAX_SECTION_ROWS)
            .ok_or(AuthorityError::Exhausted)?;
        // PostgreSQL supplied the JSON text; retain its exact UTF-8 representation.
        let bytes = format!(
            "{{\"record\":\"row\",\"section\":{},\"key\":{},\"data\":{data}}}\n",
            serde_json::to_string(section)?,
            serde_json::to_string(key)?
        )
        .into_bytes();
        let total = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|bytes| *bytes <= MAX_TRANSFER_BYTES)
            .ok_or(AuthorityError::Exhausted)?;
        self.digest
            .push(key, data.as_bytes())
            .map_err(|_| AuthorityError::Exhausted)?;
        self.count = count;
        self.bytes = total;
        Ok(bytes)
    }

    /// Do not emit until the snapshot transaction ends successfully and current
    /// live authorization is checked again. This is not an import credential.
    pub fn manifest_line(&self) -> Result<Vec<u8>, RepositoryError> {
        require(
            !self.failed
                && self.section == SECTIONS.len()
                && self.completed.len() == SECTIONS.len(),
        )?;
        let result = line(&Manifest {
            record: "manifest",
            version: 1,
            snapshot_id: self.header.snapshot_id,
            scope: self.header.scope,
            sections: &self.completed,
            content_bytes: self.bytes,
        })?;
        require(
            self.bytes
                .checked_add(result.len() as u64)
                .is_some_and(|n| n <= MAX_TRANSFER_BYTES),
        )?;
        Ok(result)
    }
}

fn line<T: Serialize>(value: &T) -> Result<Vec<u8>, RepositoryError> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}
