//! Offline, read-only predecessor metadata inspection. No key fetch or credential loading.
use serde::Serialize;
use sqlx::{PgPool, Row};

#[derive(Debug, Serialize)]
pub struct RegistrationMetadataFinding {
    pub environment_id: String,
    pub client_id: String,
    pub client_identifier: String,
    pub configuration_version_id: String,
    pub status: String,
    pub reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct RegistrationMetadataPreflight {
    pub checked_registrations: usize,
    pub findings: Vec<RegistrationMetadataFinding>,
}

/// Inspect all retained registration URI and key metadata using local runtime parsers.
///
/// Run alongside the SQL relationship report with writers stopped. This does not
/// fetch remote keys, assess cryptographic strength, or bypass normal schema startup checks.
///
/// # Errors
///
/// Returns an error on connection, transaction, query or row decoding failure. Operational
/// callers must not report successful validation in that case or print database error details.
pub async fn strict_registration_metadata_preflight(
    pool: &PgPool,
) -> Result<RegistrationMetadataPreflight, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let rows = sqlx::query(
        "SELECT c.environment_id::text, c.id::text AS client_id, c.client_identifier,
         c.configuration_version_id::text, c.status::text, c.redirect_uris,
         c.allowed_grant_types, d.post_logout_redirect_uris, d.backchannel_logout_uri,
         d.backchannel_logout_session_required, d.jwks, d.jwks_uri
         FROM aegaeon.dynamic_client_registrations d
         JOIN aegaeon.clients c ON c.environment_id=d.environment_id AND c.id=d.client_id
         ORDER BY c.environment_id,c.id",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut report = RegistrationMetadataPreflight {
        checked_registrations: rows.len(),
        findings: Vec::new(),
    };
    for row in rows {
        for reason in invalid_sources(&row)? {
            report.findings.push(RegistrationMetadataFinding {
                environment_id: row.try_get("environment_id")?,
                client_id: row.try_get("client_id")?,
                client_identifier: row.try_get("client_identifier")?,
                configuration_version_id: row.try_get("configuration_version_id")?,
                status: row.try_get("status")?,
                reason,
            });
        }
    }
    tx.rollback().await?;
    Ok(report)
}

fn invalid_sources(row: &sqlx::postgres::PgRow) -> Result<Vec<&'static str>, sqlx::Error> {
    let mut reasons = Vec::new();
    let redirects: Vec<String> = row.try_get("redirect_uris")?;
    let grants: Vec<String> = row.try_get("allowed_grant_types")?;
    if (!redirects.is_empty() || grants.iter().any(|grant| grant == "authorization_code"))
        && crate::dcr::validate_redirect_uris(&redirects).is_err()
    {
        reasons.push("invalid_redirect_uris");
    }
    let logout: Vec<String> = row.try_get("post_logout_redirect_uris")?;
    // Empty stored logout arrays represent absence; do not invent a replacement policy.
    if !logout.is_empty() && crate::dcr::validate_redirect_uris(&logout).is_err() {
        reasons.push("invalid_post_logout_redirect_uris");
    }
    let backchannel: Option<String> = row.try_get("backchannel_logout_uri")?;
    if let Some(uri) = backchannel.as_deref() {
        if crate::dcr::validate_server_callback_uri(uri, "backchannel_logout_uri").is_err() {
            reasons.push("invalid_backchannel_logout_uri");
        }
    } else if row.try_get::<bool, _>("backchannel_logout_session_required")? {
        reasons.push("backchannel_session_requires_uri");
    }
    if let Some(uri) = row.try_get::<Option<String>, _>("jwks_uri")? {
        if crate::dcr::validate_jwks_uri(&uri).is_err() {
            reasons.push("invalid_jwks_uri");
        }
    }
    if let Some(value) = row.try_get::<Option<serde_json::Value>, _>("jwks")? {
        if crate::client_registry::RegisteredClientJwks::from_value(value, false).is_err() {
            // Parser errors can contain kid/key values; emit only a fixed reason.
            reasons.push("invalid_stored_jwks");
        }
    }
    Ok(reasons)
}
