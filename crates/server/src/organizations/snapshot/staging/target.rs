//! Point-in-time reference comparison, not import authorization or a writer fence.
use super::{IntegrityReceipt, PreparationError, Result};
use crate::subject_ownership::history::{preflight, sha256_hex};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeMap;
use tokio_stream::StreamExt;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetInspection {
    namespace_receipt_id: String,
    schema_sha256: String,
    catalog_sha256: String,
    references_checked: u64,
    compatible_local_credentials: u64,
    credentials_requiring_reset_or_qualification: u64,
    complete_dependencies_checked: bool,
    activation_authorized: bool,
}

pub(super) async fn inspect(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &IntegrityReceipt,
    runtime: &str,
) -> Result<TargetInspection> {
    require(
        !runtime.is_empty() && runtime.len() <= 63,
        "target runtime role",
    )?;
    let scope = receipt.scope;
    let namespace = lookup(tx, scope.environment_id, runtime, "namespace", &[]).await?;
    require(namespace.len() == 1, "target adopted namespace missing")?;
    let namespace = namespace
        .get(&scope.environment_id.to_string())
        .ok_or(invalid("target namespace scope"))?;
    let schema = namespace["schema_sha256"]
        .as_str()
        .ok_or(invalid("target schema identity"))?;
    let catalog = lookup(tx, scope.environment_id, runtime, "catalog", &[]).await?;
    require(
        catalog.len() <= preflight::catalog_row_bound().map_err(|_| invalid("compiled catalog"))?,
        "target catalog bound",
    )?;
    let rows: Vec<_> = catalog
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    preflight::verify_compiled_catalog(&rows, schema, runtime)
        .map_err(|_| invalid("target compiled catalog mismatch"))?;
    let source_namespace: Value = sqlx::query_scalar(
        "SELECT data FROM pg_temp.organization_import_rows WHERE section='namespace'",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(PreparationError::Storage)?;
    for key in [
        "environment_id",
        "issuer_host",
        "origin",
        "contract_version",
    ] {
        require(
            namespace[key] == source_namespace[key],
            "target namespace differs from source",
        )?;
    }
    let mut report = TargetInspection {
        namespace_receipt_id: namespace["receipt_id"]
            .as_str()
            .ok_or(invalid("target namespace receipt"))?
            .into(),
        schema_sha256: schema.into(),
        catalog_sha256: sha256_hex(
            &serde_json::to_vec(&catalog).map_err(|_| invalid("catalog serialization"))?,
        ),
        references_checked: 0,
        compatible_local_credentials: 0,
        credentials_requiring_reset_or_qualification: 0,
        complete_dependencies_checked: false,
        activation_authorized: false,
    };
    for section in [
        "domain",
        "environment_dependency",
        "owners",
        "subject_history",
        "identities",
        "client_dependencies",
        "operators",
        "organizations",
        "targets",
    ] {
        compare_section(tx, receipt, runtime, section, &mut report).await?;
    }
    Ok(report)
}

async fn compare_section(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &IntegrityReceipt,
    runtime: &str,
    section: &'static str,
    report: &mut TargetInspection,
) -> Result<()> {
    let mut after: Option<String> = None;
    loop {
        let source = sqlx::query("SELECT row_key,data FROM pg_temp.organization_import_rows WHERE section=$1 AND ($2::text IS NULL OR row_key>$2 COLLATE \"C\") ORDER BY row_key LIMIT 10")
            .bind(section).bind(&after).fetch_all(&mut **tx).await.map_err(PreparationError::Storage)?;
        if source.is_empty() {
            return Ok(());
        }
        let source: Vec<(String, Value)> = source
            .into_iter()
            .map(|r| Ok((r.try_get("row_key")?, r.try_get("data")?)))
            .collect::<std::result::Result<_, sqlx::Error>>()
            .map_err(PreparationError::Storage)?;
        let keys: Result<Vec<String>> = source
            .iter()
            .map(|(k, v)| {
                if section == "operators" {
                    v["administrator_id"]
                        .as_str()
                        .map(str::to_owned)
                        .ok_or(invalid("source operator identity"))
                } else {
                    Ok(k.clone())
                }
            })
            .collect();
        let mut keys = keys?;
        keys.sort();
        keys.dedup();
        let target = lookup(tx, receipt.scope.environment_id, runtime, section, &keys).await?;
        if section == "domain" {
            for (key, row) in &source {
                require(
                    !target.contains_key(key),
                    "destination domain already exists",
                )?;
                require(
                    row["is_default"] != true || target.is_empty(),
                    "destination default domain already exists",
                )?;
            }
        } else if matches!(section, "organizations" | "targets") {
            require(
                target.is_empty(),
                "destination authority or identifier already exists",
            )?;
        } else {
            for (key, row) in &source {
                let key = if section == "operators" {
                    row["administrator_id"]
                        .as_str()
                        .ok_or(invalid("operator identity"))?
                } else {
                    key
                };
                let target = target.get(key).ok_or(invalid("target reference missing"))?;
                compare_row(tx, section, row, target, report).await?;
            }
        }
        report.references_checked = report
            .references_checked
            .checked_add(source.len() as u64)
            .ok_or(invalid("target count overflow"))?;
        after = source.last().map(|(k, _)| k.clone());
    }
}

async fn compare_row(
    tx: &mut Transaction<'_, Postgres>,
    section: &str,
    source: &Value,
    target: &Value,
    report: &mut TargetInspection,
) -> Result<()> {
    match section {
        "owners" => {
            for key in ["owner_id", "environment_id"] {
                require(
                    source[key] == target[key],
                    "target permanent owner conflict",
                )?;
            }
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_temp.organization_import_rows WHERE section='subject_history' AND data->>'owner_id'=$1")
                .bind(source["owner_id"].as_str()).fetch_one(&mut **tx).await.map_err(PreparationError::Storage)?;
            require(
                target["history_count"].as_i64() == Some(count),
                "target has missing or additional permanent subject history",
            )?;
            let current: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows WHERE section='identities' AND row_key=$1)")
                .bind(source["owner_id"].as_str()).fetch_one(&mut **tx).await.map_err(PreparationError::Storage)?;
            require(
                target["current_identity_present"] == current,
                "target deleted identity differs from source",
            )?;
        }
        "subject_history" => {
            for key in ["environment_id", "subject", "owner_id"] {
                require(source[key] == target[key], "target subject owner conflict")?;
            }
        }
        "operators" => {
            if source["active"] == true {
                require(
                    target["human_member"] == true,
                    "target operator is not a current human member",
                )?;
            }
        }
        "identities" => {
            let mut comparable = target.clone();
            let object = comparable
                .as_object_mut()
                .ok_or(invalid("target identity shape"))?;
            let active = object
                .remove("active_credentials")
                .ok_or(invalid("target credential count"))?;
            let compatible = object
                .remove("compatible_credentials")
                .ok_or(invalid("target credential profile"))?;
            require(
                source == &comparable,
                "target current identity differs from source",
            )?;
            if source["status"] == "ACTIVE" {
                if active == 1 && compatible == 1 {
                    report.compatible_local_credentials += 1;
                } else {
                    report.credentials_requiring_reset_or_qualification += 1;
                }
            }
        }
        _ => require(
            source == target,
            "target configuration or client registration differs from source",
        )?,
    }
    Ok(())
}

async fn lookup(
    tx: &mut Transaction<'_, Postgres>,
    environment: uuid::Uuid,
    runtime: &str,
    section: &str,
    keys: &[String],
) -> Result<BTreeMap<String, Value>> {
    // Catalog has a separately compiled finite bound; every other supplier
    // result is at most ten lookups plus the destination's default domain.
    let bound = if section == "catalog" {
        preflight::catalog_row_bound().map_err(|_| invalid("compiled catalog"))?
    } else {
        11
    };
    let bytes = if section == "catalog" {
        preflight::catalog_payload_bound().map_err(|_| invalid("compiled catalog byte bound"))?
    } else {
        262144 * bound
    };
    let row_bytes = if section == "catalog" { bytes } else { 262144 };
    let mut rows = sqlx::query(
        "SELECT CASE WHEN octet_length(row_key)<=4096 THEN row_key ELSE NULL END AS row_key,CASE WHEN octet_length(row_data)<=$6 THEN row_data ELSE NULL END AS row_data FROM aegaeon.organization_import_target_v1($1,$2,$3,$4) LIMIT $5",
    )
    .bind(environment)
    .bind(runtime)
    .bind(section)
    .bind(json!(keys))
    .bind((bound + 1) as i64)
    .bind(i64::try_from(row_bytes).map_err(|_| invalid("target byte bound overflow"))?)
    .fetch(&mut **tx);
    let mut result = BTreeMap::new();
    let mut consumed = 0usize;
    while let Some(row) = rows.next().await {
        let row = row.map_err(PreparationError::Storage)?;
        require(result.len() < bound, "target supplier row bound")?;
        let key: String = row.try_get("row_key").map_err(PreparationError::Storage)?;
        let raw: String = row.try_get("row_data").map_err(PreparationError::Storage)?;
        consumed = consumed
            .checked_add(raw.len())
            .filter(|n| *n <= bytes)
            .ok_or(invalid("target supplier byte bound"))?;
        require(
            raw.len() <= row_bytes && key.len() <= 4096,
            "target supplier row byte bound",
        )?;
        let value = serde_json::from_str(&raw).map_err(|_| invalid("target supplier JSON"))?;
        require(
            result.insert(key, value).is_none(),
            "target supplier duplicate key",
        )?;
    }
    Ok(result)
}

fn invalid(reason: &'static str) -> PreparationError {
    PreparationError::Invalid(reason)
}
fn require(valid: bool, reason: &'static str) -> Result<()> {
    if valid {
        Ok(())
    } else {
        Err(invalid(reason))
    }
}
