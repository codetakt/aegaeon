//! Current owned-row comparison. A prepared receipt alone is not this check.
use super::{IntegrityReceipt, PreparationError, Result};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

const SECTIONS: &[&str] = &[
    "domain",
    "targets",
    "roles",
    "client_bindings",
    "operators",
    "organizations",
    "memberships",
    "invitations",
    "challenges",
    "identity_requests",
    "administrative_grants",
    "audit",
    "receipts",
    "outbox",
];

pub(super) async fn compare(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &IntegrityReceipt,
    operation: Uuid,
) -> Result<u64> {
    if operation.is_nil() {
        return Err(PreparationError::Invalid("nil prepared operation"));
    }
    let mut total = 0_u64;
    for section in SECTIONS {
        let mut after: Option<String> = None;
        loop {
            let source: Vec<(String, Value)> = sqlx::query_as("SELECT row_key,data FROM pg_temp.organization_import_rows WHERE section=$1 AND ($2::text IS NULL OR row_key>$2 COLLATE \"C\") ORDER BY row_key LIMIT 10")
                .bind(section).bind(&after).fetch_all(&mut **tx).await.map_err(PreparationError::Storage)?;
            let target: Vec<(String, Option<String>)> = sqlx::query_as("SELECT row_key,row_data FROM aegaeon.organization_import_prepared_rows_v1($1,$2,$3,$4,$5,$6,10)")
                .bind(operation).bind(receipt.scope.environment_id).bind(receipt.scope.domain_id)
                .bind(&receipt.sha256).bind(section).bind(&after).fetch_all(&mut **tx).await.map_err(PreparationError::Storage)?;
            if source.len() != target.len() {
                return Err(PreparationError::Invalid(
                    "prepared rows missing or additional",
                ));
            }
            if source.is_empty() {
                break;
            }
            for ((key, mut expected), (actual_key, actual)) in source.into_iter().zip(target) {
                let actual =
                    actual.ok_or(PreparationError::Invalid("prepared row exceeds bound"))?;
                let actual: Value = serde_json::from_str(&actual)
                    .map_err(|_| PreparationError::Invalid("prepared row encoding"))?;
                if *section == "domain" {
                    expected["enabled"] = Value::Bool(false);
                }
                if key != actual_key || expected != actual {
                    return Err(PreparationError::Invalid(
                        "prepared row differs from retained source",
                    ));
                }
                total = total
                    .checked_add(1)
                    .ok_or(PreparationError::Invalid("prepared count overflow"))?;
                after = Some(key);
            }
        }
    }
    Ok(total)
}
