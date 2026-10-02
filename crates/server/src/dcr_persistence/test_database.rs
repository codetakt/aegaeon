//! Disposable databases for registration upgrade and HTTP tests; never alter the supplied DB.
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

pub(crate) struct Database {
    control: PgPool,
    pub(crate) pool: PgPool,
    name: String,
}

pub(crate) const MIGRATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/migrations/20261002110000_registration_metadata_consistency.sql"
));
pub(crate) const PREFLIGHT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/operations/dcr-metadata-preflight.sql"
));
pub(crate) const REPAIR: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/operations/dcr-metadata-repair.sql"
));

impl Database {
    async fn empty() -> anyhow::Result<Self> {
        let control = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
            .await?;
        let name = format!("dcr_metadata_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&control)
            .await?;
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect_with(control.connect_options().as_ref().clone().database(&name))
            .await?;
        let database = Self {
            control,
            pool,
            name,
        };
        Ok(database)
    }

    pub(crate) async fn create(predecessor: bool) -> anyhow::Result<Self> {
        let database = Self::empty().await?;
        if let Err(error) = database.initialize(predecessor).await {
            database.cleanup().await?;
            return Err(error);
        }
        Ok(database)
    }

    /// Apply every immutable source migration preceding the client-minimum upgrade.
    pub(crate) async fn client_dpop_predecessor() -> anyhow::Result<Self> {
        let database = Self::empty().await?;
        let result: anyhow::Result<()> = async {
            let directory =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../db/migrations");
            let mut paths = std::fs::read_dir(directory)?
                .map(|e| e.map(|e| e.path()))
                .collect::<Result<Vec<_>, _>>()?;
            paths.sort();
            for path in paths {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| anyhow::anyhow!("migration name"))?;
                if name.ends_with(".sql") && name < "20261002120000_client_dpop_minimum.sql" {
                    sqlx::raw_sql(&std::fs::read_to_string(&path)?)
                        .execute(&database.pool)
                        .await?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            database.cleanup().await?;
            return Err(error);
        }
        Ok(database)
    }

    async fn initialize(&self, predecessor: bool) -> anyhow::Result<()> {
        if predecessor {
            for sql in [
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20260803140000_baseline.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20260909070000_authorization_consents.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20260909090000_authorization_logins.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20260909120000_token_exchange_policy.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20260911090000_application_authorizations.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20260913090000_application_authorization_identities.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20260930090000_client_credentials_policy.sql"
                )),
            ] {
                sqlx::raw_sql(sql).execute(&self.pool).await?;
            }
        } else {
            sqlx::raw_sql(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../db/schema.sql"
            )))
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn cleanup(self) -> anyhow::Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                self.pool.close().await;
                if self.pool.size() == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
            loop {
                let connected: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=$1)",
                )
                .bind(&self.name)
                .fetch_one(&self.control)
                .await?;
                if !connected {
                    return Ok::<(), sqlx::Error>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await??;
        sqlx::query(&format!("DROP DATABASE {}", self.name))
            .execute(&self.control)
            .await?;
        self.control.close().await;
        Ok(())
    }
}
