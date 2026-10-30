use super::{IntegrityReceipt, PreparationError, Result};
use sqlx::{Postgres, Transaction};

// Fixed section/key mappings, never caller-provided SQL identifiers.
const KEYS: &[(&str, &str)] = &[
    ("domain", "id"),
    ("targets", "audience"),
    ("roles", "role_key"),
    ("client_bindings", "id"),
    ("operators", "id"),
    ("organizations", "id"),
    ("invitations", "id"),
    ("challenges", "id"),
    ("identity_requests", "id"),
    ("administrative_grants", "id"),
    ("audit", "id"),
    ("outbox", "event_id"),
    ("owners", "owner_id"),
    ("subject_history", "subject"),
    ("identities", "id"),
    ("namespace", "environment_id"),
    ("environment_dependency", "id"),
    ("client_dependencies", "id"),
];

const REFERENCES: &[(&str, &str, &str)] = &[
    ("memberships", "organization_id", "organizations"),
    ("memberships", "end_user_id", "owners"),
    ("invitations", "organization_id", "organizations"),
    ("invitations", "accepted_challenge_id", "challenges"),
    ("challenges", "invitation_id", "invitations"),
    ("identity_requests", "invitation_id", "invitations"),
    ("identity_requests", "target_user_id", "owners"),
    ("administrative_grants", "organization_id", "organizations"),
    ("administrative_grants", "user_id", "owners"),
    ("outbox", "event_id", "audit"),
    ("audit", "organization_id", "organizations"),
    ("subject_history", "owner_id", "owners"),
    ("identities", "id", "owners"),
    (
        "client_bindings",
        "client_registration_id",
        "client_dependencies",
    ),
];

pub(super) async fn check(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &IntegrityReceipt,
) -> Result<()> {
    for (section, id) in [
        ("domain", receipt.scope.domain_id),
        ("namespace", receipt.scope.environment_id),
        ("environment_dependency", receipt.scope.environment_id),
    ] {
        let valid: bool = sqlx::query_scalar("SELECT count(*)=1 AND bool_and(row_key=$2) FROM pg_temp.organization_import_rows WHERE section=$1")
            .bind(section).bind(id.to_string()).fetch_one(&mut **tx).await.map_err(PreparationError::Storage)?;
        require(valid, "missing or conflicting scope dependency")?;
    }
    for (section, field) in KEYS {
        let invalid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows WHERE section=$1 AND row_key IS DISTINCT FROM data->>$2)")
            .bind(section).bind(field).fetch_one(&mut **tx).await.map_err(PreparationError::Storage)?;
        require(!invalid, "source key does not identify its row")?;
    }
    for (section, field, target) in REFERENCES {
        let invalid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows s WHERE s.section=$1 AND s.data->>$2 IS NOT NULL AND NOT EXISTS(SELECT FROM pg_temp.organization_import_rows t WHERE t.section=$3 AND t.row_key=s.data->>$2))")
            .bind(section).bind(field).bind(target).fetch_one(&mut **tx).await.map_err(PreparationError::Storage)?;
        require(!invalid, "missing retained source dependency")?;
    }
    for (query, reason) in CHECKS {
        let invalid: bool = sqlx::query_scalar(query)
            .fetch_one(&mut **tx)
            .await
            .map_err(PreparationError::Storage)?;
        require(!invalid, reason)?;
    }
    Ok(())
}

fn require(value: bool, reason: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(PreparationError::Invalid(reason))
    }
}

const CHECKS: &[(&str, &str)] = &[
    ("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows o WHERE o.section='owners' AND NOT EXISTS(SELECT FROM pg_temp.organization_import_rows r WHERE (r.section='memberships' AND r.data->>'end_user_id'=o.row_key) OR (r.section='identity_requests' AND (r.data->>'target_user_id'=o.row_key OR r.data->'result'->>'userId'=o.row_key)) OR (r.section='challenges' AND r.data->'recipient_binding'->'binding'->>'user_id'=o.row_key) OR (r.section='administrative_grants' AND r.data->>'user_id'=o.row_key)))", "owner is outside this source domain's retained references"),
    ("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows WHERE section='memberships' AND row_key IS DISTINCT FROM jsonb_build_array(data->'organization_id',data->'end_user_id')::text)", "membership key is not canonical"),
    ("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows WHERE section='receipts' AND row_key IS DISTINCT FROM jsonb_build_array(data->'actor_id',data->'actor_kind',data->'client_id',data->'client_registration_id',data->'operation',data->'idempotency_key')::text)", "receipt key is not canonical"),
    ("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows WHERE section='organizations' GROUP BY data->>'external_id' COLLATE \"C\" HAVING count(*)>1)", "external identifier ownership conflict"),
    ("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows i WHERE i.section='identities' AND NOT EXISTS(SELECT FROM pg_temp.organization_import_rows h WHERE h.section='subject_history' AND h.row_key=i.data->>'subject' AND h.data->>'owner_id'=i.row_key))", "current subject has no permanent owner reservation"),
    ("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows o WHERE o.section='owners' AND NOT EXISTS(SELECT FROM pg_temp.organization_import_rows h WHERE h.section='subject_history' AND h.data->>'owner_id'=o.row_key))", "owner history is incomplete"),
    ("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows c WHERE c.section='challenges' AND NOT EXISTS(SELECT FROM pg_temp.organization_import_rows o WHERE o.section='owners' AND o.row_key=c.data->'recipient_binding'->'binding'->>'user_id'))", "challenge owner history is incomplete"),
    ("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows r WHERE r.section='identity_requests' AND r.data->'result'<>'null'::jsonb AND NOT EXISTS(SELECT FROM pg_temp.organization_import_rows o WHERE o.section='owners' AND o.row_key=r.data->'result'->>'userId'))", "completed identity owner history is incomplete"),
    ("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows i JOIN pg_temp.organization_import_rows c ON c.section='challenges' AND c.row_key=i.data->>'accepted_challenge_id' WHERE i.section='invitations' AND c.data->>'invitation_id' IS DISTINCT FROM i.row_key)", "accepted challenge belongs to another invitation"),
    ("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows b JOIN pg_temp.organization_import_rows c ON c.section='client_dependencies' AND c.row_key=b.data->>'client_registration_id' WHERE b.section='client_bindings' AND b.data->>'client_identifier' IS DISTINCT FROM c.data->>'client_identifier')", "client registration identifier mismatch"),
];
