use crate::config::DatabaseConfig;
use anyhow::{bail, Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::time::Duration;

const ATLAS_SUM: &str = include_str!("../../../db/migrations/atlas.sum");

/// Connect the required `PostgreSQL` pool.
///
/// # Errors
///
/// Returns an error when `SQLx` cannot establish the requested connection pool.
pub async fn connect_required_pool(cfg: &DatabaseConfig) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .acquire_timeout(Duration::from_secs(cfg.acquire_timeout_secs))
        .connect(cfg.url())
        .await?;

    Ok(pool)
}

/// Verify that the connected `PostgreSQL` database is at the source-managed
/// Atlas migration head.
///
/// # Errors
///
/// Returns an error when Atlas revision metadata is absent, stale, failed, or
/// inconsistent with the migration inventory compiled into this binary.
pub async fn preflight_required_schema_revision(pool: &PgPool) -> Result<()> {
    let expected = expected_atlas_head_revision()?;
    let revision_table = atlas_revision_table_name(pool).await?;
    let row = sqlx::query(&format!(
        r#"
SELECT version, description, hash, applied, total, error
FROM {revision_table}
WHERE version = $1 OR version = $2
ORDER BY executed_at DESC
LIMIT 1
"#
    ))
    .bind(expected.version)
    .bind(expected.stem)
    .fetch_optional(pool)
    .await
    .context("failed to query Atlas schema revision metadata")?;

    let Some(row) = row else {
        bail!(
            "PostgreSQL schema is not at the Aegaeon migration head: expected Atlas revision {} ({})",
            expected.version,
            expected.file_name,
        );
    };

    let version: String = row.try_get("version")?;
    let description: Option<String> = row.try_get("description")?;
    let hash: Option<String> = row.try_get("hash")?;
    let applied: i64 = row.try_get("applied")?;
    let total: i64 = row.try_get("total")?;
    let error: Option<String> = row.try_get("error")?;

    if error.as_deref().is_some_and(|value| !value.is_empty()) {
        bail!("PostgreSQL schema revision {version} has failed Atlas metadata: {error:?}");
    }
    if total <= 0 || applied != total {
        bail!("PostgreSQL schema revision {version} is partial: applied {applied} of {total}");
    }
    if version != expected.version && version != expected.stem {
        bail!(
            "PostgreSQL schema revision mismatch: expected {} or {}, got {}",
            expected.version,
            expected.stem,
            version
        );
    }
    if version == expected.version
        && description
            .as_deref()
            .is_some_and(|value| value != expected.description)
    {
        bail!(
            "PostgreSQL schema revision description mismatch for {}: expected {}, got {:?}",
            expected.version,
            expected.description,
            description
        );
    }
    if hash
        .as_deref()
        .is_some_and(|value| !expected.accepts_hash(value))
    {
        bail!(
            "PostgreSQL schema revision hash mismatch for {}: expected {}, got {:?}",
            expected.version,
            expected.file_hash,
            hash
        );
    }

    Ok(())
}

async fn atlas_revision_table_name(pool: &PgPool) -> Result<String> {
    sqlx::query_scalar::<_, String>(
        r#"
SELECT format('%I.%I', table_schema, table_name)
FROM information_schema.tables
WHERE table_name = 'atlas_schema_revisions'
  AND table_type = 'BASE TABLE'
  AND table_schema IN (current_schema(), 'public', 'aegaeon')
ORDER BY
  CASE
    WHEN table_schema = current_schema() THEN 0
    WHEN table_schema = 'public' THEN 1
    ELSE 2
  END
LIMIT 1
"#,
    )
    .fetch_optional(pool)
    .await
    .context("failed to locate Atlas schema revision metadata")?
    .ok_or_else(|| {
        anyhow::anyhow!(
            "PostgreSQL schema revision metadata table atlas_schema_revisions is missing; apply the source-managed Atlas migrations before starting the server"
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpectedAtlasRevision<'a> {
    file_name: &'a str,
    stem: &'a str,
    version: &'a str,
    description: &'a str,
    file_hash: &'a str,
    atlas_sum_hash: &'a str,
}

impl ExpectedAtlasRevision<'_> {
    fn accepts_hash(&self, hash: &str) -> bool {
        let hash = hash.strip_prefix("h1:").unwrap_or(hash);
        [self.file_hash, self.atlas_sum_hash]
            .into_iter()
            .filter_map(|expected| expected.strip_prefix("h1:"))
            .any(|expected| hash == expected)
    }
}

fn expected_atlas_head_revision() -> Result<ExpectedAtlasRevision<'static>> {
    parse_atlas_head_revision(ATLAS_SUM)
        .ok_or_else(|| anyhow::anyhow!("db/migrations/atlas.sum does not contain a migration head"))
}

fn parse_atlas_head_revision(sum: &'static str) -> Option<ExpectedAtlasRevision<'static>> {
    let mut lines = sum.lines().map(str::trim).filter(|line| !line.is_empty());
    let atlas_sum_hash = lines.next()?;
    let head = lines.next_back()?;
    let mut fields = head.split_whitespace();
    let file_name = fields.next()?;
    let file_hash = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    let stem = file_name.strip_suffix(".sql")?;
    let (version, description) = stem.split_once('_')?;
    Some(ExpectedAtlasRevision {
        file_name,
        stem,
        version,
        description,
        file_hash,
        atlas_sum_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_atlas_head_revision;

    #[test]
    fn parses_atlas_head_revision() {
        let head = parse_atlas_head_revision(
            r#"
h1:sum
20260101000000_init.sql h1:init
20260630140000_verified_crypto_profile_only.sql h1:file
"#,
        )
        .expect("atlas head should parse");

        assert_eq!(
            head.file_name,
            "20260630140000_verified_crypto_profile_only.sql"
        );
        assert_eq!(head.stem, "20260630140000_verified_crypto_profile_only");
        assert_eq!(head.version, "20260630140000");
        assert_eq!(head.description, "verified_crypto_profile_only");
        assert!(head.accepts_hash("h1:file"));
        assert!(head.accepts_hash("h1:sum"));
        assert!(head.accepts_hash("file"));
        assert!(head.accepts_hash("sum"));
        assert!(!head.accepts_hash("other"));
    }
}
