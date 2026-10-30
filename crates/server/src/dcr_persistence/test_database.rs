//! Disposable databases for registration upgrade and HTTP tests; never alter the supplied DB.
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

pub(crate) struct Database {
    control: PgPool,
    pub(crate) pool: PgPool,
    pub(crate) admin: PgPool,
    name: String,
}

pub(crate) const MIGRATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/migrations/20261027020000_registration_metadata_consistency.sql"
));
pub(crate) const PUBLIC_JWK_MIGRATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/migrations/20261027010000_public_client_jwk_storage.sql"
));

#[derive(Clone, Copy)]
enum Schema {
    Current,
    MetadataPredecessor,
    PublicJwkPredecessor,
    ClientSecretPredecessor,
    ClientDpopPredecessor,
}

pub(crate) const PREFLIGHT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/operations/dcr-metadata-preflight.sql"
));
pub(crate) const REPAIR: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/operations/dcr-metadata-repair.sql"
));

impl Database {
    pub(crate) async fn create(predecessor: bool) -> anyhow::Result<Self> {
        Self::create_with_schema(if predecessor {
            Schema::MetadataPredecessor
        } else {
            Schema::Current
        })
        .await
    }

    pub(crate) async fn before_public_jwk_upgrade() -> anyhow::Result<Self> {
        Self::create_with_schema(Schema::PublicJwkPredecessor).await
    }

    pub(crate) async fn before_client_secret_upgrade() -> anyhow::Result<Self> {
        Self::create_with_schema(Schema::ClientSecretPredecessor).await
    }

    /// Apply every immutable source migration before the client-minimum upgrade.
    pub(crate) async fn client_dpop_predecessor() -> anyhow::Result<Self> {
        Self::create_with_schema(Schema::ClientDpopPredecessor).await
    }

    async fn create_with_schema(schema: Schema) -> anyhow::Result<Self> {
        let control = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
            .await?;
        let name = format!("initialization_dcr_{}", Uuid::new_v4().simple());
        if matches!(schema, Schema::Current) {
            crate::web::test_support::prepare_child_database(&name).await?;
        } else {
            sqlx::query(&format!("CREATE DATABASE {name}"))
                .execute(&control)
                .await?;
        }
        let admin = PgPoolOptions::new()
            .max_connections(6)
            .connect_with(control.connect_options().as_ref().clone().database(&name))
            .await?;
        let pool = if matches!(schema, Schema::Current) {
            let options: sqlx::postgres::PgConnectOptions =
                std::env::var("AEGAEON_DATABASE_URL")?.parse()?;
            PgPoolOptions::new()
                .max_connections(6)
                .connect_with(options.database(&name))
                .await?
        } else {
            admin.clone()
        };
        let database = Self {
            control,
            pool,
            admin,
            name,
        };
        let result = database.initialize(schema).await;
        if let Err(error) = result {
            database.cleanup().await?;
            return Err(error);
        }
        Ok(database)
    }

    async fn initialize(&self, schema: Schema) -> anyhow::Result<()> {
        if matches!(schema, Schema::ClientDpopPredecessor) {
            // Compile immutable migration bytes into the package. Build directories
            // do not exist when the packaged executable runs outside its sandbox.
            for migration in [
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
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261002100000_federation_entity_cache_expiration.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261012000000_logout_confirmations.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261013090000_account_link_provenance.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261027000000_introspection_signing_key_slots.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261027010000_public_client_jwk_storage.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261027020000_registration_metadata_consistency.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261029010000_access_token_rs256_signing.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261029020000_client_secret_active_slots.sql"
                )),
            ] {
                sqlx::raw_sql(migration).execute(&self.pool).await?;
            }
            return Ok(());
        }
        if !matches!(schema, Schema::Current) {
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
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261002100000_federation_entity_cache_expiration.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261012000000_logout_confirmations.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261013090000_account_link_provenance.sql"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261027000000_introspection_signing_key_slots.sql"
                )),
            ] {
                sqlx::raw_sql(sql).execute(&self.pool).await?;
            }
            if matches!(
                schema,
                Schema::MetadataPredecessor | Schema::ClientSecretPredecessor
            ) {
                sqlx::query(PUBLIC_JWK_MIGRATION)
                    .execute(&self.pool)
                    .await?;
            }
            if matches!(schema, Schema::ClientSecretPredecessor) {
                sqlx::raw_sql(MIGRATION).execute(&self.pool).await?;
                sqlx::raw_sql(include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/20261029010000_access_token_rs256_signing.sql"
                )))
                .execute(&self.pool)
                .await?;
            }
            // Older component-upgrade tests use current server helpers to create
            // their fixtures. Add the unrelated DPoP shape while this DB is empty;
            // their target migration/constraints remain absent. These are isolated
            // component fixtures, not a chronological production upgrade prefix.
            // ClientDpopPredecessor above retains the exact complete prefix.
            sqlx::raw_sql(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../db/migrations/20261029030000_client_dpop_minimum.sql"
            )))
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn cleanup(self) -> anyhow::Result<()> {
        self.admin.close().await;
        let drained = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
        .await;
        match drained {
            Ok(result) => result?,
            Err(error) => {
                // Preserve the original cleanup deadline. Collect bounded
                // ownership diagnostics rather than retrying or forcing DROP.
                let sessions = tokio::time::timeout(std::time::Duration::from_secs(1),
                    sqlx::query_as::<_, (i32, String, Option<String>, Option<String>, Option<String>)>(
                        "SELECT pid,backend_type,state,wait_event_type,wait_event FROM pg_stat_activity WHERE datname=$1"
                    ).bind(&self.name).fetch_all(&self.control)).await;
                anyhow::bail!("owned database cleanup deadline: size={}, idle={}, sessions={sessions:?}; {error}", self.pool.size(), self.pool.num_idle());
            }
        }
        sqlx::query(&format!("DROP DATABASE {}", self.name))
            .execute(&self.control)
            .await?;
        self.control.close().await;
        Ok(())
    }
}
