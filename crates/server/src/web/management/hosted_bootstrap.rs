use anyhow::{anyhow, bail, Context, Result};
use axum::response::Response;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::management::types::PolicyDocument;

mod input;
mod kms_runtime;
mod model;
mod observability_seed;

use super::configuration_documents::{
    default_policy_document, parse_activated_environment_configuration,
    prepare_configuration_document,
};
use super::configuration_version_store::persist_environment_configuration_state;
use super::{begin_management_transaction, commit_management_transaction, hash_password};
use input::normalize_input;
use kms_runtime::insert_oidc_kms_runtime_key;
use model::{ExistingBootstrap, NormalizedHostedBootstrapInput};
pub use model::{HostedBootstrapInput, HostedBootstrapOutput, HostedBootstrapStatus};
pub use observability_seed::{
    seed_observability_environment, ObservabilitySeedOutput, ObservabilitySeedStatus,
};

const BOOTSTRAP_LOCK_ID: i64 = 724_617_524;

pub async fn bootstrap_hosted_environment(
    pool: &PgPool,
    input: HostedBootstrapInput,
) -> Result<HostedBootstrapOutput> {
    let input = normalize_input(input)?;
    let mut tx = begin_management_transaction(pool, "hosted-bootstrap")
        .await
        .map_err(response_error)?;

    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(BOOTSTRAP_LOCK_ID)
        .execute(&mut *tx)
        .await
        .context("failed to acquire hosted bootstrap advisory lock")?;

    if let Some(existing) = load_existing_bootstrap(&mut tx, &input.issuer_host).await? {
        commit_management_transaction(tx, "hosted-bootstrap")
            .await
            .map_err(response_error)?;
        return Ok(output_from_existing(
            HostedBootstrapStatus::AlreadyInitialized,
            &input,
            existing,
        ));
    }

    fail_if_management_plane_initialized(&mut tx).await?;

    let administrator_id = insert_administrator(&mut tx, &input).await?;
    let team_id = insert_team(&mut tx, &input).await?;
    insert_team_owner(&mut tx, team_id, administrator_id).await?;
    let tenant_id = insert_tenant(&mut tx, team_id, &input).await?;
    let environment_id = insert_environment(&mut tx, tenant_id, &input).await?;
    let configuration_version_id =
        insert_active_configuration(&mut tx, environment_id, administrator_id, &input).await?;
    activate_environment(&mut tx, environment_id, configuration_version_id).await?;
    let runtime_key_id =
        insert_oidc_kms_runtime_key(&mut tx, environment_id, configuration_version_id, &input)
            .await?;

    commit_management_transaction(tx, "hosted-bootstrap")
        .await
        .map_err(response_error)?;

    Ok(HostedBootstrapOutput {
        status: HostedBootstrapStatus::Created,
        issuer_host: input.issuer_host,
        issuer_url: input.issuer_url,
        team_id,
        tenant_id,
        environment_id,
        configuration_version_id,
        runtime_key_id,
    })
}

fn output_from_existing(
    status: HostedBootstrapStatus,
    input: &NormalizedHostedBootstrapInput,
    existing: ExistingBootstrap,
) -> HostedBootstrapOutput {
    HostedBootstrapOutput {
        status,
        issuer_host: input.issuer_host.clone(),
        issuer_url: input.issuer_url.clone(),
        team_id: existing.team_id,
        tenant_id: existing.tenant_id,
        environment_id: existing.environment_id,
        configuration_version_id: existing.configuration_version_id,
        runtime_key_id: existing.runtime_key_id,
    }
}

async fn load_existing_bootstrap(
    tx: &mut Transaction<'_, Postgres>,
    issuer_host: &str,
) -> Result<Option<ExistingBootstrap>> {
    let row = sqlx::query(
        r"
SELECT
  t.id AS team_id,
  tn.id AS tenant_id,
  e.id AS environment_id,
  e.active_configuration_version_id AS configuration_version_id,
  rk.id AS runtime_key_id
FROM aegaeon.environments e
JOIN aegaeon.tenants tn ON tn.id = e.tenant_id
JOIN aegaeon.teams t ON t.id = tn.team_id
JOIN aegaeon.configuration_versions cv ON cv.id = e.active_configuration_version_id
JOIN aegaeon.runtime_keys rk
  ON rk.environment_id = e.id
 AND rk.usage = 'OIDC_ID_TOKEN_SIGNING'
 AND rk.status = 'ACTIVE'
WHERE e.issuer_host = $1
  AND e.status = 'ACTIVE'
  AND cv.status = 'ACTIVE'
ORDER BY e.id
LIMIT 1
        ",
    )
    .bind(issuer_host)
    .fetch_optional(&mut **tx)
    .await?;

    row.map(|row| {
        Ok(ExistingBootstrap {
            team_id: row.try_get("team_id")?,
            tenant_id: row.try_get("tenant_id")?,
            environment_id: row.try_get("environment_id")?,
            configuration_version_id: row.try_get("configuration_version_id")?,
            runtime_key_id: row.try_get("runtime_key_id")?,
        })
    })
    .transpose()
}

async fn fail_if_management_plane_initialized(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    let initialized: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM aegaeon.administrators)")
            .fetch_one(&mut **tx)
            .await?;
    if initialized {
        bail!("management plane already contains administrators; refusing hosted bootstrap");
    }
    Ok(())
}

async fn insert_administrator(
    tx: &mut Transaction<'_, Postgres>,
    input: &NormalizedHostedBootstrapInput,
) -> Result<Uuid> {
    let password_hash = hash_password(&input.owner_password).map_err(response_error)?;
    sqlx::query_scalar(
        r"
INSERT INTO aegaeon.administrators (email, password_hash)
VALUES ($1, $2)
RETURNING id
        ",
    )
    .bind(&input.owner_email)
    .bind(password_hash)
    .fetch_one(&mut **tx)
    .await
    .context("failed to create hosted bootstrap administrator")
}

async fn insert_team(
    tx: &mut Transaction<'_, Postgres>,
    input: &NormalizedHostedBootstrapInput,
) -> Result<Uuid> {
    sqlx::query_scalar(
        r"
INSERT INTO aegaeon.teams (name, slug)
VALUES ($1, $2)
RETURNING id
        ",
    )
    .bind(&input.team_name)
    .bind(&input.team_slug)
    .fetch_one(&mut **tx)
    .await
    .context("failed to create hosted bootstrap team")
}

async fn insert_team_owner(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    administrator_id: Uuid,
) -> Result<()> {
    sqlx::query(
        r"
INSERT INTO aegaeon.team_memberships (team_id, administrator_id, role)
VALUES ($1, $2, 'OWNER')
        ",
    )
    .bind(team_id)
    .bind(administrator_id)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .context("failed to create hosted bootstrap team owner membership")
}

async fn insert_tenant(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    input: &NormalizedHostedBootstrapInput,
) -> Result<Uuid> {
    sqlx::query_scalar(
        r"
INSERT INTO aegaeon.tenants (team_id, slug, name, region)
VALUES ($1, $2, $3, $4)
RETURNING id
        ",
    )
    .bind(team_id)
    .bind(&input.tenant_slug)
    .bind(&input.tenant_name)
    .bind(&input.tenant_region)
    .fetch_one(&mut **tx)
    .await
    .context("failed to create hosted bootstrap tenant")
}

async fn insert_environment(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    input: &NormalizedHostedBootstrapInput,
) -> Result<Uuid> {
    sqlx::query_scalar(
        r"
INSERT INTO aegaeon.environments (tenant_id, name, slug, issuer_host)
VALUES ($1, $2, $3, $4)
RETURNING id
        ",
    )
    .bind(tenant_id)
    .bind(&input.environment_name)
    .bind(&input.environment_slug)
    .bind(&input.issuer_host)
    .fetch_one(&mut **tx)
    .await
    .context("failed to create hosted bootstrap environment")
}

async fn insert_active_configuration(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    administrator_id: Uuid,
    input: &NormalizedHostedBootstrapInput,
) -> Result<Uuid> {
    let document = initial_configuration_document(input);
    insert_active_configuration_document(
        tx,
        environment_id,
        administrator_id,
        input,
        document,
        "hosted-bootstrap",
        "Hosted bootstrap initial configuration",
    )
    .await
}

async fn insert_active_configuration_document(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    administrator_id: Uuid,
    input: &NormalizedHostedBootstrapInput,
    document: serde_json::Value,
    request_id: &str,
    comment: &str,
) -> Result<Uuid> {
    let prepared = prepare_configuration_document(&document, request_id)
        .map_err(response_error)
        .context("bootstrap configuration document validation failed")?;
    let configuration_version_id = sqlx::query_scalar(
        r"
INSERT INTO aegaeon.configuration_versions (
  environment_id,
  version_number,
  schema_version,
  configuration_hash,
  status,
  configuration_document,
  created_by_administrator_id,
  comment,
  activated_at
)
VALUES ($1, 1, 1, $2, 'ACTIVE', $3::jsonb, $4, $5, now())
RETURNING id
        ",
    )
    .bind(environment_id)
    .bind(prepared.hash)
    .bind(prepared.document)
    .bind(administrator_id)
    .bind(comment)
    .fetch_one(&mut **tx)
    .await
    .context("failed to create hosted bootstrap configuration version")?;

    let activated = parse_activated_environment_configuration(
        document,
        &input.issuer_host,
        &input.issuer_url,
        request_id,
    )
    .map_err(response_error)
    .context("bootstrap activated configuration validation failed")?;
    persist_environment_configuration_state(
        tx,
        environment_id,
        configuration_version_id,
        &activated.state,
        request_id,
    )
    .await
    .map_err(response_error)
    .context("bootstrap configuration projection persistence failed")?;

    Ok(configuration_version_id)
}

fn initial_configuration_document(input: &NormalizedHostedBootstrapInput) -> serde_json::Value {
    let mut policy = default_policy_document();
    apply_hosted_policy(&mut policy);
    serde_json::json!({
        "schemaVersion": 1,
        "issuerHost": input.issuer_host,
        "issuerUrl": input.issuer_url,
        "policy": policy,
        "scopeAllowlist": ["openid", "profile", "email"],
        "clients": [],
        "keyStore": {
            "type": "databaseEncrypted",
            "configuration": {},
            "redacted": true,
        },
    })
}

fn apply_hosted_policy(policy: &mut PolicyDocument) {
    policy.oidc_enabled = true;
    policy.oidc_enable_discovery = true;
    policy.oidc_enable_userinfo = true;
    policy.oidc_require_nonce = true;
    policy.dcr_enabled = false;
    policy.dpop_strict = true;
    policy.dpop_require_nonce = true;
    policy.require_state_parameter = true;
    policy.strict_authorize_redirect = true;
    policy.require_client_auth_token = true;
    policy.require_client_auth_par = true;
    policy.require_pushed_authorization_requests = true;
    policy.require_client_auth_introspection = true;
    policy.require_client_auth_revocation = true;
}

async fn activate_environment(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
) -> Result<()> {
    sqlx::query(
        r"
UPDATE aegaeon.environments
SET active_configuration_version_id = $1, updated_at = now()
WHERE id = $2
        ",
    )
    .bind(configuration_version_id)
    .bind(environment_id)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .context("failed to activate hosted bootstrap environment configuration")
}

fn response_error(response: Response) -> anyhow::Error {
    anyhow!(
        "management bootstrap validation failed with status {}",
        response.status()
    )
}
