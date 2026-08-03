use sqlx::{postgres::PgRow, Row};
use uuid::Uuid;

use super::types::{PasswordCredentialRecord, RecoveryTokenRecord, RuntimeEnvironmentContext};

pub(super) fn runtime_environment_context_from_row(
    row: &PgRow,
) -> Result<RuntimeEnvironmentContext, sqlx::Error> {
    Ok(RuntimeEnvironmentContext {
        team_id: row.try_get("team_id")?,
        tenant_id: row.try_get("tenant_id")?,
        environment_id: row.try_get("environment_id")?,
    })
}

pub(super) fn password_credential_record_from_row(
    row: &PgRow,
) -> Result<PasswordCredentialRecord, sqlx::Error> {
    Ok(PasswordCredentialRecord {
        id: row.try_get::<Uuid, _>("id")?.to_string(),
        status: row.try_get("status")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        last_used_at: row.try_get("last_used_at")?,
    })
}

pub(super) fn recovery_token_record_from_row(
    row: &PgRow,
) -> Result<RecoveryTokenRecord, sqlx::Error> {
    Ok(RecoveryTokenRecord {
        id: row.try_get::<Uuid, _>("id")?.to_string(),
        purpose: row.try_get("purpose")?,
        status: row.try_get("status")?,
        expires_at: row.try_get("expires_at")?,
        redeemed_at: row.try_get("redeemed_at")?,
        revoked_at: row.try_get("revoked_at")?,
        created_at: row.try_get("created_at")?,
    })
}
