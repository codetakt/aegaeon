use super::{parse_atlas_revisions, preflight_required_schema_revision, ATLAS_SUM};
use anyhow::{ensure, Context, Result};
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};

struct Fixture {
    pool: PgPool,
    schema: String,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let url = std::env::var("AEGAEON_DATABASE_URL")
            .context("AEGAEON_DATABASE_URL is required for this ignored PostgreSQL test")?;
        let schema = format!("schema_preflight_{}", uuid::Uuid::new_v4().simple());
        let search_path = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |connection, _| {
                let search_path = search_path.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('search_path', $1, false)")
                        .bind(search_path)
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await?;
        pool.execute(format!("CREATE SCHEMA {schema}").as_str())
            .await?;
        let fixture = Self { pool, schema };
        fixture
            .pool
            .execute(
                "CREATE TABLE atlas_schema_revisions (
                    version text PRIMARY KEY, description text, hash text,
                    applied bigint NOT NULL, total bigint NOT NULL, error text,
                    executed_at timestamptz NOT NULL DEFAULT now()
                )",
            )
            .await?;
        fixture.reset().await?;
        Ok(fixture)
    }

    async fn reset(&self) -> Result<()> {
        self.pool
            .execute("DELETE FROM atlas_schema_revisions")
            .await?;
        for revision in parse_atlas_revisions(ATLAS_SUM).context("compiled inventory")? {
            sqlx::query(
                "INSERT INTO atlas_schema_revisions
                 (version, description, hash, applied, total)
                 VALUES ($1, $2, $3, 1, 1)",
            )
            .bind(revision.version)
            .bind(revision.description)
            .bind(revision.file_hash)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn extra_revision(&self, version: &str) -> Result<()> {
        // A later schema revision can have an older timestamp after restoration
        // or a clock change. Selection by executed_at must not hide it.
        sqlx::query(
            "INSERT INTO atlas_schema_revisions
             (version, applied, total, executed_at) VALUES ($1, 1, 1, '2000-01-01')",
        )
        .bind(version)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn refuses(&self, message: &str) -> Result<()> {
        let error = preflight_required_schema_revision(&self.pool)
            .await
            .err()
            .context("schema preflight unexpectedly accepted this database")?;
        ensure!(
            error.to_string().contains(message),
            "unexpected refusal: {error}"
        );
        Ok(())
    }

    async fn finish(self, result: Result<()>) -> Result<()> {
        let cleanup = self
            .pool
            .execute(format!("DROP SCHEMA {} CASCADE", self.schema).as_str())
            .await;
        self.pool.close().await;
        cleanup.context("remove the owned schema preflight fixture")?;
        result
    }
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_schema_preflight_accepts_known_and_legacy_revisions() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        preflight_required_schema_revision(&fixture.pool).await?;
        for revision in parse_atlas_revisions(ATLAS_SUM).context("inventory")? {
            sqlx::query("UPDATE atlas_schema_revisions SET version = $1 WHERE version = $2")
                .bind(revision.stem)
                .bind(revision.version)
                .execute(&fixture.pool)
                .await?;
        }
        preflight_required_schema_revision(&fixture.pool).await?;
        // Retain the existing compatibility with missing legacy hash metadata.
        fixture
            .pool
            .execute("UPDATE atlas_schema_revisions SET hash = NULL")
            .await?;
        preflight_required_schema_revision(&fixture.pool).await
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_schema_preflight_rejects_newer_revision_with_known_head_present() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        preflight_required_schema_revision(&fixture.pool).await?;
        fixture.extra_revision("99990101000000").await?;
        fixture
            .refuses("unsupported Atlas revision 99990101000000")
            .await?;
        fixture.reset().await?;
        preflight_required_schema_revision(&fixture.pool).await
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_schema_preflight_rejects_unknown_prior_revision() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        fixture.extra_revision("00000101000000_unknown").await?;
        fixture.refuses("unsupported Atlas revision").await
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_schema_preflight_rejects_duplicate_revision_alias() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let inventory = parse_atlas_revisions(ATLAS_SUM).context("inventory")?;
        let head = inventory.last().context("head")?;
        fixture.extra_revision(head.stem).await?;
        fixture.refuses("duplicate Atlas revision").await
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_schema_preflight_rejects_incomplete_historical_revision() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let inventory = parse_atlas_revisions(ATLAS_SUM).context("inventory")?;
        let first = inventory.first().context("first migration")?;
        sqlx::query("UPDATE atlas_schema_revisions SET applied = 0 WHERE version = $1")
            .bind(first.version).execute(&fixture.pool).await?;
        fixture.refuses("is partial").await?;
        sqlx::query("UPDATE atlas_schema_revisions SET applied = 1, error = 'migration failed' WHERE version = $1")
            .bind(first.version).execute(&fixture.pool).await?;
        fixture.refuses("has failed Atlas metadata").await?;
        fixture.reset().await?;
        preflight_required_schema_revision(&fixture.pool).await
    }.await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_schema_preflight_requires_matching_head_metadata() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let inventory = parse_atlas_revisions(ATLAS_SUM).context("inventory")?;
        let head = inventory.last().context("head")?;
        for (statement, message) in [
            (
                "DELETE FROM atlas_schema_revisions WHERE version = $1",
                "not at the Aegaeon migration head",
            ),
            (
                "UPDATE atlas_schema_revisions SET hash = 'h1:wrong' WHERE version = $1",
                "hash mismatch",
            ),
            (
                "UPDATE atlas_schema_revisions SET description = 'wrong' WHERE version = $1",
                "description mismatch",
            ),
            (
                "UPDATE atlas_schema_revisions SET total = 0 WHERE version = $1",
                "is partial",
            ),
        ] {
            sqlx::query(statement)
                .bind(head.version)
                .execute(&fixture.pool)
                .await?;
            fixture.refuses(message).await?;
            fixture.reset().await?;
            preflight_required_schema_revision(&fixture.pool).await?;
        }
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
