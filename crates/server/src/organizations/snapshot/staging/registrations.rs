//! Exact current/absent dependencies, independently reconstructed from input.
use super::{PreparationError, Result};
use serde_json::Value;
use sqlx::{Postgres, Transaction};

const REFERENCES: &str = r#"WITH refs AS (
  SELECT data->>'client_registration_id' AS id FROM pg_temp.organization_import_rows WHERE section='client_bindings'
  UNION SELECT r->>'clientRegistrationId' FROM pg_temp.organization_import_rows t CROSS JOIN LATERAL jsonb_array_elements(t.data->'introspection_clients') r WHERE t.section='targets'
  UNION SELECT data->'authority'->'actor'->>'client_registration_id' FROM pg_temp.organization_import_rows WHERE section='invitations' AND data->'authority'->'actor'->>'kind'='member'
  UNION SELECT data->'recipient_binding'->'binding'->>'client_registration_id' FROM pg_temp.organization_import_rows WHERE section='challenges'
  UNION SELECT data->>'client_registration_id' FROM pg_temp.organization_import_rows WHERE section='administrative_grants'
  UNION SELECT data->>'client_registration_id' FROM pg_temp.organization_import_rows WHERE section IN ('audit','receipts') AND data->>'actor_kind'='member'
), wanted AS (SELECT id FROM refs WHERE id IS NOT NULL), supplied AS (
  SELECT row_key AS id FROM pg_temp.organization_import_rows WHERE section IN ('client_dependencies','client_absences')
) SELECT NOT EXISTS((SELECT id FROM wanted EXCEPT SELECT id FROM supplied)
                   UNION ALL (SELECT id FROM supplied EXCEPT SELECT id FROM wanted))
  AND NOT EXISTS(SELECT id FROM supplied GROUP BY id HAVING count(*)<>1)"#;

const CONNECTIONS: &str = r#"WITH wanted AS (
  SELECT p->>'connectionId' AS id FROM pg_temp.organization_import_rows d CROSS JOIN LATERAL jsonb_array_elements(d.data->'support_policy'->'providers') p WHERE d.section='domain'
), supplied AS (SELECT row_key AS id FROM pg_temp.organization_import_rows WHERE section='connection_dependencies')
SELECT NOT EXISTS((SELECT id FROM wanted EXCEPT SELECT id FROM supplied)
                  UNION ALL (SELECT id FROM supplied EXCEPT SELECT id FROM wanted))"#;

pub(super) async fn check(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    for (query, reason) in [
        (
            REFERENCES,
            "retained client references differ from current and absent registrations",
        ),
        (
            CONNECTIONS,
            "support provider references differ from connection dependencies",
        ),
    ] {
        if !sqlx::query_scalar::<_, bool>(query)
            .fetch_one(&mut **tx)
            .await
            .map_err(PreparationError::Storage)?
        {
            return Err(PreparationError::Invalid(reason));
        }
    }
    Ok(())
}

pub(super) fn validate_connection(row: &Value) -> std::result::Result<(), &'static str> {
    if row["present"] == false {
        return if row["configuration"].is_null() {
            Ok(())
        } else {
            Err("absent provider has configuration")
        };
    }
    let value = row["configuration"]
        .as_object()
        .ok_or("present provider has no configuration")?;
    let columns = "id:uuid environment_id:uuid configuration_version_id:uuid connection_identifier:text connection_type:text issuer_url:text client_id:text client_auth_method:text status:text deleted_at:?text";
    let mut count = 0;
    for descriptor in columns.split_whitespace() {
        let (name, kind) = descriptor
            .split_once(':')
            .ok_or("compiled provider contract")?;
        if !value
            .get(name)
            .is_some_and(|v| super::contracts::matches_kind(v, kind))
        {
            return Err("provider column type or range");
        }
        count += 1;
    }
    if value.len() != count
        || value["id"] != row["id"]
        || value["environment_id"] != row["environment_id"]
    {
        return Err("provider identity or closed projection");
    }
    Ok(())
}
