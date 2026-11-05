//! Read-only native credential compatibility, never activation or history adoption.
use anyhow::{ensure, Result};
use argon2::password_hash::{PasswordHash, SaltString};
use serde_json::{json, Value};
use sqlx::{Connection, PgConnection, Postgres, Row, Transaction};
use std::path::Path;
use tokio_stream::StreamExt;
use uuid::Uuid;

const MAX_ROWS: i64 = 100_000;
const MAX_BYTES: i64 = 64 * 1024 * 1024;
const MAX_CELL: i64 = 65_536;

// This is the existing native/import Argon2id profile. Parsing compatibility
// does not prove knowledge of the password or change/reset the credential.
fn password_profile(value: &str) -> Result<()> {
    ensure!(value.len() <= 1024, "credential profile size");
    let parsed = PasswordHash::new(value).map_err(|_| anyhow::anyhow!("credential encoding"))?;
    ensure!(
        parsed.algorithm.as_str() == "argon2id"
            && parsed.version == Some(19)
            && parsed.params.to_string() == "m=19456,t=2,p=1"
            && parsed.hash.is_some_and(|h| h.len() == 32),
        "unsupported credential profile"
    );
    let salt = parsed
        .salt
        .ok_or_else(|| anyhow::anyhow!("credential salt absent"))?;
    let mut decoded = [0u8; 16];
    let bytes = salt
        .decode_b64(&mut decoded)
        .map_err(|_| anyhow::anyhow!("credential salt encoding"))?;
    ensure!(
        bytes.len() == 16
            && SaltString::encode_b64(bytes)
                .map_err(|_| anyhow::anyhow!("credential salt encoding"))?
                .as_str()
                == salt.as_str()
            && parsed.to_string() == value,
        "noncanonical credential profile"
    );
    Ok(())
}

pub(super) async fn inspect(ca: &Path, environment: Uuid, issuer: &str) -> Result<Value> {
    ensure!(!environment.is_nil(), "explicit Environment required");
    super::super::witness::connector::no_ambient_postgres()?;
    let endpoint = std::env::var("AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL")?;
    let options =
        super::transport::postgres_options(&endpoint, ca, super::transport::certificate(ca)?)?
            .application_name("aegaeon-organization-credential-inspect");
    let mut connection =
        tokio::time::timeout(super::DEADLINE, PgConnection::connect_with(&options)).await??;
    let namespace = crate::web::namespace_runtime::validate_connection_inputs(
        &mut connection,
        environment,
        issuer,
    )
    .await?;
    let observation = super::primary(&mut connection).await?;
    let result = inspect_connection(&mut connection, environment).await?;
    connection.close().await?;
    Ok(
        json!({"environmentId":environment,"namespaceReceiptId":namespace,
        "primary":observation,"compatibility":result,"primaryClosed":true,
        "activationAuthorized":false}),
    )
}

async fn inspect_connection(connection: &mut PgConnection, environment: Uuid) -> Result<Value> {
    let mut tx = connection.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL transaction_timeout='20s'")
        .execute(&mut *tx)
        .await?;
    let passwords = hashes(&mut tx, environment, false).await?;
    let clients = hashes(&mut tx, environment, true).await?;
    let upstream = upstream(&mut tx, environment).await?;
    let keys = keys(&mut tx, environment).await?;
    tx.rollback().await?;
    Ok(
        json!({"localPasswordProfiles":passwords,"clientSecretProfiles":clients,
        "upstreamSecretsDecrypted":upstream,"runtimeKeysValidated":keys,
        "passwordKnowledgeChecked":false,"futureExternalKeyAvailabilityQualified":false}),
    )
}

async fn bounded(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    query: &str,
) -> Result<i64> {
    let row: (i64, i64, i64) = sqlx::query_as(query)
        .bind(environment)
        .fetch_one(&mut **tx)
        .await?;
    ensure!(
        row.0 <= MAX_ROWS && row.1 <= MAX_BYTES && row.2 <= MAX_CELL,
        "credential inspection budget exceeded"
    );
    Ok(row.0)
}

async fn hashes(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    clients: bool,
) -> Result<i64> {
    let source = if clients {
        "SELECT secret_hash AS value,secret_hash_algorithm AS algorithm FROM aegaeon.client_secrets WHERE environment_id=$1 AND status='ACTIVE'"
    } else {
        "SELECT p.password_hash AS value,'argon2id'::text AS algorithm FROM aegaeon.end_user_password_credentials p JOIN aegaeon.end_users u ON u.id=p.end_user_id WHERE u.environment_id=$1 AND p.status='ACTIVE'"
    };
    // Only fixed source strings above are composed. No input supplies SQL.
    let budget = format!("SELECT count(*)::bigint,COALESCE(sum(octet_length(value)),0)::bigint,COALESCE(max(octet_length(value)),0)::bigint FROM ({source}) s");
    let count = bounded(tx, environment, &budget).await?;
    let mut rows = sqlx::query(source).bind(environment).fetch(&mut **tx);
    while let Some(row) = rows.try_next().await? {
        ensure!(
            row.try_get::<&str, _>("algorithm")? == "argon2id",
            "credential algorithm"
        );
        password_profile(row.try_get("value")?)?;
    }
    Ok(count)
}

async fn upstream(tx: &mut Transaction<'_, Postgres>, environment: Uuid) -> Result<i64> {
    let count = bounded(tx, environment,
        "SELECT count(*)::bigint,COALESCE(sum(octet_length(client_secret_encrypted)),0)::bigint,COALESCE(max(octet_length(client_secret_encrypted)),0)::bigint FROM aegaeon.connections WHERE environment_id=$1 AND client_secret_encrypted IS NOT NULL"
    ).await?;
    let mut rows = sqlx::query("SELECT id,client_secret_encrypted FROM aegaeon.connections WHERE environment_id=$1 AND client_secret_encrypted IS NOT NULL")
        .bind(environment).fetch(&mut **tx);
    while let Some(row) = rows.try_next().await? {
        let secret = crate::upstream::open_upstream_client_secret(
            row.try_get("client_secret_encrypted")?,
            environment,
            row.try_get("id")?,
        )
        .map_err(|_| anyhow::anyhow!("upstream credential incompatible"))?;
        ensure!(!secret.is_empty(), "empty upstream credential");
    }
    Ok(count)
}

async fn keys(tx: &mut Transaction<'_, Postgres>, environment: Uuid) -> Result<usize> {
    let count = bounded(tx, environment,
        "SELECT count(*)::bigint,COALESCE(sum(pg_column_size(r)),0)::bigint,COALESCE(max(pg_column_size(r)),0)::bigint FROM aegaeon.runtime_keys r WHERE environment_id=$1 AND status<>'REVOKED'"
    ).await?;
    ensure!(count <= 1024, "runtime key budget exceeded");
    let rows = sqlx::query("SELECT environment_id,usage::text AS usage,algorithm,provider::text AS provider,status::text AS status,EXTRACT(EPOCH FROM retiring_expires_at)::bigint AS retiring_expires_at_epoch_secs,kid,public_jwk,key_handle,provider_configuration FROM aegaeon.runtime_keys WHERE environment_id=$1 AND status<>'REVOKED' ORDER BY id")
        .bind(environment).fetch_all(&mut **tx).await?;
    let keys = rows
        .iter()
        .map(crate::runtime_keys::runtime_key_from_row)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    crate::runtime_keys::RuntimeKeySet::try_new(keys.clone())?;
    for key in &keys {
        use crate::runtime_keys::RuntimeKeyUsage;
        match key.usage {
            RuntimeKeyUsage::OidcIdTokenSigning | RuntimeKeyUsage::OidcRequestObjectDecryption => {
                crate::oidc::config::validate_restored_oidc_key(key).await?
            }
            RuntimeKeyUsage::JwtAccessTokenSigning | RuntimeKeyUsage::JwtIntrospectionSigning => {
                crate::kms::validate_restored_jwt_key(key)?
            }
        }
    }
    Ok(keys.len())
}

#[cfg(test)]
mod tests;
