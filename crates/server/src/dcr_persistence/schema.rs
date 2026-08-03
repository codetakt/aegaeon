use super::DcrDatabaseError;
use sqlx::{PgPool, Row};
use std::collections::BTreeSet;

const DCR_SCHEMA_NAME: &str = "aegaeon";
const DCR_TABLE_NAME: &str = "dynamic_client_registrations";
const DCR_TABLE_QUALIFIED_NAME: &str = "aegaeon.dynamic_client_registrations";
const DCR_MIGRATION_HINT: &str = "the aegaeon schema baseline (atlas migrate apply --env local)";
const DCR_BEARER_TABLE_NAME: &str = "environment_dcr_bearer_tokens";
const DCR_BEARER_TABLE_QUALIFIED_NAME: &str = "aegaeon.environment_dcr_bearer_tokens";
const DCR_BEARER_MIGRATION_HINT: &str =
    "the aegaeon schema baseline (atlas migrate apply --env local)";
pub(crate) const REQUIRED_DCR_COLUMNS: &[&str] = &[
    "environment_id",
    "client_id",
    "client_identifier",
    "registration_access_token_hash",
    "registration_access_token_hash_algorithm",
    "client_id_issued_at",
    "response_types",
    "post_logout_redirect_uris",
    "backchannel_logout_uri",
    "backchannel_logout_session_required",
    "jwks_uri",
    "jwks",
    "token_endpoint_auth_signing_alg",
    "created_at",
    "updated_at",
];
pub(crate) const REQUIRED_DCR_INDEXES: &[&str] = &[
    "dynamic_client_registrations_env_identifier_unique",
    "dynamic_client_registrations_env_token_hash_unique",
];
pub(crate) const REQUIRED_DCR_CONSTRAINTS: &[&str] = &[
    "dynamic_client_registrations_pkey",
    "dynamic_client_registrations_hash_algorithm",
    "dynamic_client_registrations_token_hash_shape",
];
const REQUIRED_DCR_BEARER_COLUMNS: &[&str] = &[
    "environment_id",
    "token_hash",
    "token_hash_algorithm",
    "created_at",
    "updated_at",
];
const REQUIRED_DCR_BEARER_CONSTRAINTS: &[&str] = &[
    "environment_dcr_bearer_tokens_pkey",
    "environment_dcr_bearer_tokens_hash_algorithm",
    "environment_dcr_bearer_tokens_hash_shape",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DynamicRegistrationSchemaInventory {
    pub(crate) columns: BTreeSet<String>,
    pub(crate) indexes: BTreeSet<String>,
    pub(crate) constraints: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DynamicRegistrationSchemaDeficit {
    pub(crate) missing_columns: Vec<&'static str>,
    pub(crate) missing_indexes: Vec<&'static str>,
    pub(crate) missing_constraints: Vec<&'static str>,
}

impl DynamicRegistrationSchemaDeficit {
    pub(crate) fn from_inventory(inventory: &DynamicRegistrationSchemaInventory) -> Self {
        Self {
            missing_columns: missing_required_items(&inventory.columns, REQUIRED_DCR_COLUMNS),
            missing_indexes: missing_required_items(&inventory.indexes, REQUIRED_DCR_INDEXES),
            missing_constraints: missing_required_items(
                &inventory.constraints,
                REQUIRED_DCR_CONSTRAINTS,
            ),
        }
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.missing_columns.is_empty()
            && self.missing_indexes.is_empty()
            && self.missing_constraints.is_empty()
    }

    #[must_use]
    pub(crate) fn describe(&self, table_missing: bool) -> String {
        self.describe_for(table_missing, DCR_TABLE_QUALIFIED_NAME, DCR_MIGRATION_HINT)
    }

    #[must_use]
    fn describe_for(
        &self,
        table_missing: bool,
        table_qualified_name: &'static str,
        migration_path: &'static str,
    ) -> String {
        if table_missing {
            return format!(
                "missing or inaccessible {table_qualified_name}; apply {migration_path}"
            );
        }

        let details = [
            describe_missing("columns", &self.missing_columns),
            describe_missing("indexes", &self.missing_indexes),
            describe_missing("constraints", &self.missing_constraints),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
        format!(
            "{table_qualified_name} is missing required schema items ({details}); apply {migration_path}"
        )
    }
}

pub async fn preflight_dynamic_registration_schema(pool: &PgPool) -> Result<(), DcrDatabaseError> {
    let inventory = load_dynamic_registration_schema_inventory(pool).await?;
    let deficit = DynamicRegistrationSchemaDeficit::from_inventory(&inventory);
    if !deficit.is_empty() {
        return Err(DcrDatabaseError::SchemaPreflight(
            deficit.describe(inventory.columns.is_empty()),
        ));
    }

    let bearer_inventory = load_schema_inventory(pool, DCR_BEARER_TABLE_NAME).await?;
    let bearer_deficit = DynamicRegistrationSchemaDeficit {
        missing_columns: missing_required_items(
            &bearer_inventory.columns,
            REQUIRED_DCR_BEARER_COLUMNS,
        ),
        missing_indexes: Vec::new(),
        missing_constraints: missing_required_items(
            &bearer_inventory.constraints,
            REQUIRED_DCR_BEARER_CONSTRAINTS,
        ),
    };
    if !bearer_deficit.is_empty() {
        return Err(DcrDatabaseError::SchemaPreflight(
            bearer_deficit.describe_for(
                bearer_inventory.columns.is_empty(),
                DCR_BEARER_TABLE_QUALIFIED_NAME,
                DCR_BEARER_MIGRATION_HINT,
            ),
        ));
    }

    Ok(())
}

async fn load_dynamic_registration_schema_inventory(
    pool: &PgPool,
) -> Result<DynamicRegistrationSchemaInventory, DcrDatabaseError> {
    load_schema_inventory(pool, DCR_TABLE_NAME).await
}

async fn load_schema_inventory(
    pool: &PgPool,
    table_name: &str,
) -> Result<DynamicRegistrationSchemaInventory, DcrDatabaseError> {
    let columns = sqlx::query(
        r"
SELECT column_name
FROM information_schema.columns
WHERE table_schema = $1
  AND table_name = $2
        ",
    )
    .bind(DCR_SCHEMA_NAME)
    .bind(table_name)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| row.try_get::<String, _>("column_name"))
    .collect::<Result<BTreeSet<_>, _>>()?;

    let indexes = sqlx::query(
        r"
SELECT indexname
FROM pg_indexes
WHERE schemaname = $1
  AND tablename = $2
        ",
    )
    .bind(DCR_SCHEMA_NAME)
    .bind(table_name)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| row.try_get::<String, _>("indexname"))
    .collect::<Result<BTreeSet<_>, _>>()?;

    let constraints = sqlx::query(
        r"
SELECT c.conname
FROM pg_catalog.pg_constraint c
JOIN pg_catalog.pg_class t
  ON t.oid = c.conrelid
JOIN pg_catalog.pg_namespace n
  ON n.oid = t.relnamespace
WHERE n.nspname = $1
  AND t.relname = $2
        ",
    )
    .bind(DCR_SCHEMA_NAME)
    .bind(table_name)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| row.try_get::<String, _>("conname"))
    .collect::<Result<BTreeSet<_>, _>>()?;

    Ok(DynamicRegistrationSchemaInventory {
        columns,
        indexes,
        constraints,
    })
}

fn missing_required_items(
    present: &BTreeSet<String>,
    required: &'static [&'static str],
) -> Vec<&'static str> {
    required
        .iter()
        .copied()
        .filter(|item| !present.contains(*item))
        .collect()
}

fn describe_missing(label: &'static str, missing: &[&'static str]) -> Option<String> {
    (!missing.is_empty()).then(|| format!("missing {label}: {}", missing.join(", ")))
}
