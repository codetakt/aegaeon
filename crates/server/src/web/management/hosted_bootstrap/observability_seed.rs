use anyhow::{bail, Context, Result};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::management::types::ApiKeyCapability;
use crate::runtime_configuration::normalize_runtime_issuer_host_selector;

use super::model::NormalizedHostedBootstrapInput;
use super::{
    activate_environment, commit_management_transaction, default_policy_document,
    fail_if_management_plane_initialized, insert_active_configuration_document,
    insert_administrator, insert_environment, insert_team, insert_team_owner, insert_tenant,
    response_error, BOOTSTRAP_LOCK_ID,
};
use crate::web::management::{
    api_keys::{insert_api_key_row, ApiKeyInsertInput},
    begin_management_transaction, sha256_array,
};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilitySeedStatus {
    Created,
    AlreadyInitialized,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservabilitySeedOutput {
    pub status: ObservabilitySeedStatus,
    pub issuer_host: String,
    pub issuer_url: String,
    pub team_id: Uuid,
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub configuration_version_id: Uuid,
    pub api_key_id: Uuid,
}

struct ExistingSeed {
    team_id: Uuid,
    tenant_id: Uuid,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    api_key_id: Uuid,
}

/// Seed a minimal OIDC-disabled runtime configuration for local observability checks.
///
/// # Errors
///
/// Returns an error when the issuer is not loopback-only, the management plane contains a
/// different bootstrap, or the validated configuration cannot be persisted.
pub async fn seed_observability_environment(
    pool: &PgPool,
    issuer_host: &str,
    raw_api_key: &str,
) -> Result<ObservabilitySeedOutput> {
    let input = normalize_seed_input(issuer_host)?;
    let (key_prefix, key_hash) = validate_api_key(raw_api_key)?;
    let mut tx = begin_management_transaction(pool, "observability-seed")
        .await
        .map_err(response_error)?;

    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(BOOTSTRAP_LOCK_ID)
        .execute(&mut *tx)
        .await
        .context("failed to acquire observability seed advisory lock")?;

    if let Some(existing) =
        load_existing_seed(&mut tx, &input.issuer_host, &key_prefix, &key_hash).await?
    {
        commit_management_transaction(tx, "observability-seed")
            .await
            .map_err(response_error)?;
        return Ok(output_from_existing(&input, existing));
    }

    fail_if_management_plane_initialized(&mut tx).await?;

    let administrator_id = insert_administrator(&mut tx, &input).await?;
    insert_default_control_plane_policy(&mut tx).await?;
    let team_id = insert_team(&mut tx, &input).await?;
    insert_team_owner(&mut tx, team_id, administrator_id).await?;
    let api_key_id =
        insert_observability_api_key(&mut tx, team_id, administrator_id, &key_prefix, &key_hash)
            .await?;
    let tenant_id = insert_tenant(&mut tx, team_id, &input).await?;
    let environment_id = insert_environment(&mut tx, tenant_id, &input).await?;
    let document = oidc_off_configuration_document(&input);
    let configuration_version_id = insert_active_configuration_document(
        &mut tx,
        environment_id,
        administrator_id,
        &input,
        document,
        "observability-seed",
        "OIDC-off observability seed configuration",
    )
    .await?;
    activate_environment(&mut tx, environment_id, configuration_version_id).await?;

    commit_management_transaction(tx, "observability-seed")
        .await
        .map_err(response_error)?;

    Ok(ObservabilitySeedOutput {
        status: ObservabilitySeedStatus::Created,
        issuer_host: input.issuer_host,
        issuer_url: input.issuer_url,
        team_id,
        tenant_id,
        environment_id,
        configuration_version_id,
        api_key_id,
    })
}

async fn insert_default_control_plane_policy(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    sqlx::query("INSERT INTO aegaeon.control_plane_policies (id) VALUES ('default')")
        .execute(&mut **tx)
        .await
        .map(|_| ())
        .context("failed to create default control-plane policy")
}

fn validate_api_key(raw_api_key: &str) -> Result<(String, [u8; 32])> {
    if !raw_api_key.starts_with("aeg_")
        || raw_api_key.chars().count() < 12
        || raw_api_key.chars().any(char::is_whitespace)
    {
        bail!("observability seed API key must use the aeg_ format");
    }
    Ok((
        raw_api_key.chars().take(12).collect(),
        sha256_array(raw_api_key.as_bytes()),
    ))
}

async fn insert_observability_api_key(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    administrator_id: Uuid,
    key_prefix: &str,
    key_hash: &[u8; 32],
) -> Result<Uuid> {
    let api_key_id = Uuid::new_v4();
    if let Err(response) = insert_api_key_row(
        tx,
        &ApiKeyInsertInput {
            api_key_id,
            team_id,
            service_administrator_id: Uuid::new_v4(),
            name: "Observability metrics reader",
            key_prefix,
            key_hash,
            capabilities: &[ApiKeyCapability::AuditRead],
            expires_in_days: Some(1),
            created_by_administrator_id: administrator_id,
        },
        "observability-seed",
    )
    .await
    {
        return Err(response_error(response))
            .context("failed to create observability metrics API key");
    }
    Ok(api_key_id)
}

fn normalize_seed_input(issuer_host: &str) -> Result<NormalizedHostedBootstrapInput> {
    let issuer_host = normalize_runtime_issuer_host_selector(issuer_host)
        .ok_or_else(|| anyhow::anyhow!("observability seed issuer host is invalid"))?;
    let issuer_url = format!("https://{issuer_host}");
    let parsed = url::Url::parse(&issuer_url).context("failed to parse observability issuer")?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("observability seed issuer must include a host"))?;
    if !crate::util::is_loopback_host(host) {
        bail!("observability seed issuer must be a loopback host");
    }

    Ok(NormalizedHostedBootstrapInput {
        issuer_host,
        issuer_url,
        owner_email: "observability-seed@localhost.invalid".to_string(),
        owner_password: format!("{}!Aa9", Uuid::new_v4()),
        team_name: "Observability Seed".to_string(),
        team_slug: "observability-seed".to_string(),
        tenant_name: "Observability Tenant".to_string(),
        tenant_slug: "observability".to_string(),
        tenant_region: "local".to_string(),
        environment_name: "Observability Runtime".to_string(),
        environment_slug: "runtime".to_string(),
        kms_region: String::new(),
        kms_key_id: String::new(),
        kms_kid: String::new(),
    })
}

async fn load_existing_seed(
    tx: &mut Transaction<'_, Postgres>,
    issuer_host: &str,
    key_prefix: &str,
    key_hash: &[u8; 32],
) -> Result<Option<ExistingSeed>> {
    let row = sqlx::query(
        r"
SELECT
  t.id AS team_id,
  tn.id AS tenant_id,
  e.id AS environment_id,
  e.active_configuration_version_id AS configuration_version_id,
  ak.id AS api_key_id
FROM aegaeon.environments e
JOIN aegaeon.tenants tn ON tn.id = e.tenant_id
JOIN aegaeon.teams t ON t.id = tn.team_id
JOIN aegaeon.configuration_versions cv ON cv.id = e.active_configuration_version_id
JOIN aegaeon.api_keys ak ON ak.team_id = t.id
JOIN aegaeon.administrators sa ON sa.id = ak.service_administrator_id
WHERE e.issuer_host = $1
  AND e.status = 'ACTIVE'
  AND cv.status = 'ACTIVE'
  AND COALESCE((cv.configuration_document->'policy'->>'oidcEnabled')::boolean, false) = false
  AND ak.key_prefix = $2
  AND ak.key_hash = $3
  AND ak.status = 'ACTIVE'
  AND (ak.expires_at IS NULL OR ak.expires_at > now())
  AND sa.status = 'ACTIVE'
  AND sa.kind = 'SERVICE'
  AND EXISTS (
    SELECT 1
    FROM aegaeon.api_key_capabilities akc
    WHERE akc.api_key_id = ak.id
      AND akc.capability = 'AUDIT_READ'
  )
ORDER BY e.id
LIMIT 1
        ",
    )
    .bind(issuer_host)
    .bind(key_prefix)
    .bind(key_hash.as_slice())
    .fetch_optional(&mut **tx)
    .await?;

    row.map(|row| {
        Ok(ExistingSeed {
            team_id: row.try_get("team_id")?,
            tenant_id: row.try_get("tenant_id")?,
            environment_id: row.try_get("environment_id")?,
            configuration_version_id: row.try_get("configuration_version_id")?,
            api_key_id: row.try_get("api_key_id")?,
        })
    })
    .transpose()
}

fn oidc_off_configuration_document(input: &NormalizedHostedBootstrapInput) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 1,
        "issuerHost": input.issuer_host,
        "issuerUrl": input.issuer_url,
        "policy": default_policy_document(),
        "scopeAllowlist": ["openid", "profile", "email"],
        "keyStore": {
            "type": "databaseEncrypted",
            "configuration": {},
            "redacted": true,
        },
    })
}

fn output_from_existing(
    input: &NormalizedHostedBootstrapInput,
    existing: ExistingSeed,
) -> ObservabilitySeedOutput {
    ObservabilitySeedOutput {
        status: ObservabilitySeedStatus::AlreadyInitialized,
        issuer_host: input.issuer_host.clone(),
        issuer_url: input.issuer_url.clone(),
        team_id: existing.team_id,
        tenant_id: existing.tenant_id,
        environment_id: existing.environment_id,
        configuration_version_id: existing.configuration_version_id,
        api_key_id: existing.api_key_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_input_accepts_only_loopback_hosts() {
        let input = normalize_seed_input("127.0.0.1:8080").expect("loopback seed should normalize");
        assert_eq!(input.issuer_host, "127.0.0.1:8080");
        assert_eq!(input.issuer_url, "https://127.0.0.1:8080");

        assert!(normalize_seed_input("issuer.example.com").is_err());
    }

    #[test]
    fn seed_api_key_requires_management_key_shape() {
        assert!(validate_api_key("aeg_0123456789abcdef").is_ok());
        assert!(validate_api_key("not-a-key").is_err());
    }

    #[test]
    fn seed_document_keeps_oidc_disabled() {
        let input = normalize_seed_input("localhost:8080").expect("loopback seed should normalize");
        let document = oidc_off_configuration_document(&input);

        assert_eq!(document["policy"]["oidcEnabled"], false);
        assert_eq!(document["policy"]["jwtAccessTokensEnabled"], false);
    }
}
