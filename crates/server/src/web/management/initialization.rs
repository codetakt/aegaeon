//! Explicit operator initialization before starting the server.
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};

use super::topology_support::{
    build_initial_environment_configuration, create_environment_with_initial_configuration,
    CreateEnvironmentInput,
};
use super::transactions::{
    begin_bootstrap_transaction, commit_management_transaction,
    write_management_control_plane_audit_event, ManagementControlPlaneAuditEvent,
};
use super::{
    hash_password, normalize_email, validate_bootstrap_owner_password, ManagementEnvironmentScope,
    ManagementTenantScope,
};
use uuid::Uuid;

// Deliberately no Debug or Serialize: this value contains the owner password.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InitializationInput {
    pub owner_email: String,
    pub owner_password: String,
    pub allowed_origins: Vec<String>,
    pub issuer_base_domain: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializationOutput {
    pub administrator_id: Uuid,
    pub team_id: Uuid,
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub configuration_version_id: Uuid,
    pub issuer_host: String,
}

/// Initialize an empty management database. Database access authorizes this action.
///
/// # Errors
/// Rejects invalid inputs, an already initialized database and persistence failures.
pub async fn initialize_management(
    pool: &PgPool,
    input: &InitializationInput,
) -> Result<InitializationOutput> {
    let validated = normalize_input(input)?;
    let team_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let scope = ManagementTenantScope {
        team: team_id,
        tenant: tenant_id,
        slug: "primary".into(),
        region: "local".into(),
    };
    let environment = CreateEnvironmentInput {
        slug: "dev".into(),
        name: "Development".into(),
    };
    let configuration = build_initial_environment_configuration(
        &validated.base_domain,
        &scope,
        &environment,
        "management-initialization",
    )
    .map_err(response_error)?;
    let mut tx = begin_bootstrap_transaction(pool, "management-initialization")
        .await
        .map_err(response_error)?;
    let initialized: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM aegaeon.administrators) OR EXISTS (SELECT 1 FROM aegaeon.control_plane_policies)")
        .fetch_one(&mut *tx).await.map_err(|_| anyhow!("failed to check initialization status"))?;
    if initialized {
        bail!("management database already initialized; refusing to replace credentials or policy");
    }
    let administrator_id = insert_initial_authority(&mut tx, &scope, &validated).await?;
    let created = create_environment_with_initial_configuration(
        &mut tx,
        &scope,
        &environment,
        &configuration,
        administrator_id,
        "management-initialization",
    )
    .await
    .map_err(response_error)?;
    write_management_control_plane_audit_event(
        &mut tx,
        ManagementControlPlaneAuditEvent {
            scope: ManagementEnvironmentScope {
                team: team_id,
                tenant: tenant_id,
                environment: created.environment_id,
            },
            administrator_id,
            request_id: "management-initialization",
            event_type: "MANAGEMENT_INITIALIZED",
            target_type: "ENVIRONMENT",
            target_id: created.environment_id.to_string(),
            data: serde_json::json!({"allowedOrigins": validated.origins, "issuerBaseDomain": validated.base_domain}),
        },
    )
    .await
    .map_err(response_error)?;
    commit_management_transaction(tx, "management-initialization")
        .await
        .map_err(response_error)?;
    Ok(InitializationOutput {
        administrator_id,
        team_id,
        tenant_id,
        environment_id: created.environment_id,
        configuration_version_id: created.configuration_version_id,
        issuer_host: configuration.issuer_host,
    })
}

// Do not expose response bodies or SQL row details through the operator command.
#[expect(
    clippy::needless_pass_by_value,
    reason = "owned Result::map_err callback"
)]
fn response_error(response: axum::response::Response) -> anyhow::Error {
    anyhow!(
        "management initialization failed with status {}",
        response.status()
    )
}

struct ValidatedInitialization {
    email: String,
    password_hash: String,
    origins: Vec<String>,
    base_domain: String,
}

fn normalize_input(input: &InitializationInput) -> Result<ValidatedInitialization> {
    let email =
        normalize_email(&input.owner_email).ok_or_else(|| anyhow!("invalid owner email"))?;
    validate_bootstrap_owner_password(&input.owner_password)
        .map_err(|_| anyhow!("invalid owner password"))?;
    if input.allowed_origins.is_empty() || input.allowed_origins.len() > 32 {
        bail!("allowedOrigins must contain between 1 and 32 unique HTTPS origins");
    }
    let mut origins = Vec::new();
    for origin in &input.allowed_origins {
        let normalized = super::state::normalize_management_allowed_origin(origin)
            .map_err(|_| anyhow!("invalid allowed origin"))?;
        if origins.contains(&normalized) {
            bail!("duplicate allowed origin");
        }
        origins.push(normalized);
    }
    let base_domain =
        super::host_validation::normalize_dns_name(&input.issuer_base_domain, "issuer base domain")
            .map_err(|_| anyhow!("invalid issuer base domain"))?;
    let password_hash = hash_password(&input.owner_password).map_err(response_error)?;
    Ok(ValidatedInitialization {
        email,
        password_hash,
        origins,
        base_domain,
    })
}

async fn insert_initial_authority(
    tx: &mut Transaction<'_, Postgres>,
    scope: &ManagementTenantScope,
    input: &ValidatedInitialization,
) -> Result<Uuid> {
    let administrator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO aegaeon.administrators (email, password_hash) VALUES ($1, $2) RETURNING id",
    )
    .bind(&input.email)
    .bind(&input.password_hash)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| anyhow!("failed to create owner"))?;
    sqlx::query("INSERT INTO aegaeon.control_plane_policies (id, management_allowed_origins, management_issuer_base_domain) VALUES ('default', $1, $2)")
        .bind(&input.origins).bind(&input.base_domain).execute(&mut **tx).await
        .map_err(|_| anyhow!("failed to create control-plane policy"))?;
    sqlx::query(
        "INSERT INTO aegaeon.teams (id, name, slug) VALUES ($1, 'Primary Team', 'primary')",
    )
    .bind(scope.team)
    .execute(&mut **tx)
    .await
    .map_err(|_| anyhow!("failed to create initial team"))?;
    super::insert_team_owner_membership(
        tx,
        scope.team,
        administrator_id,
        "management-initialization",
    )
    .await
    .map_err(response_error)?;
    sqlx::query("INSERT INTO aegaeon.tenants (id, team_id, name, slug, region) VALUES ($1, $2, 'Primary Tenant', 'primary', 'local')")
        .bind(scope.tenant).bind(scope.team).execute(&mut **tx).await
        .map_err(|_| anyhow!("failed to create initial tenant"))?;
    Ok(administrator_id)
}
