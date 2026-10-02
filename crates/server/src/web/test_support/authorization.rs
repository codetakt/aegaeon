//! Real loader fixtures with an isolated synthetic key-encryption environment.
use super::*;
use crate::config::ServerConfig;
use crate::runtime_configuration::{AuthorizationRuntime, DatabaseRuntimeConfiguration};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

const FIXTURE_KEK: [u8; 32] = [0x57; 32];

pub(crate) async fn seed_oidc_configuration(
    pool: &PgPool,
    env: &TestEnvironment,
    policy: PolicyDocument,
    kid: &str,
) -> TestResult {
    let pem = include_str!("../../../tests/fixtures/rsa2048-private.pk8.pem");
    let signing = crate::oidc::OidcSigningKey::from_rsa_pem(kid.into(), pem)?;
    let der = pem::parse(pem)?;
    let encrypted = crate::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(der.contents()),
        &FIXTURE_KEK,
        crate::key_encryption::KeyHandleEncryptionContext::new(
            env.environment_id,
            "OIDC_ID_TOKEN_SIGNING",
            "databaseEncrypted",
            "RS256",
            kid,
        ),
    )?;
    let mut tx = pool.begin().await?;
    let configuration: Uuid = sqlx::query_scalar(
        "UPDATE aegaeon.configuration_versions SET configuration_document=jsonb_set(configuration_document,'{policy}',$1) WHERE environment_id=$2 AND status='ACTIVE' RETURNING id",
    ).bind(serde_json::to_value(policy)?).bind(env.environment_id).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO aegaeon.runtime_keys(environment_id,configuration_version_id,usage,kid,algorithm,provider,status,public_jwk,key_handle) VALUES($1,$2,'OIDC_ID_TOKEN_SIGNING',$3,'RS256','databaseEncrypted','ACTIVE',$4,$5)")
        .bind(env.environment_id).bind(configuration).bind(kid)
        .bind(serde_json::to_value(&signing.jwks().keys[0])?).bind(encrypted).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

/// Add a real managed encryption key to the active fixture configuration.
pub(crate) async fn seed_request_object_encryption_key(
    state: &mut AppState,
    kid: &str,
    private_der: &[u8],
) -> TestResult {
    let key = crate::oidc::config::OidcRequestObjectEncryptionKey::from_rsa_pkcs8_der(
        kid.to_string(),
        private_der,
    )?;
    let encrypted = crate::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(private_der),
        &FIXTURE_KEK,
        crate::key_encryption::KeyHandleEncryptionContext::new(
            state.environment_id,
            "OIDC_REQUEST_OBJECT_DECRYPTION",
            "databaseEncrypted",
            "RSA-OAEP+A256GCM",
            kid,
        ),
    )?;
    sqlx::query("INSERT INTO aegaeon.runtime_keys(environment_id,configuration_version_id,usage,kid,algorithm,provider,status,public_jwk,key_handle)
        SELECT environment_id,id,'OIDC_REQUEST_OBJECT_DECRYPTION',$2,'RSA-OAEP+A256GCM','databaseEncrypted','ACTIVE',$3,$4
        FROM aegaeon.configuration_versions WHERE environment_id=$1 AND status='ACTIVE'")
        .bind(state.environment_id).bind(kid).bind(serde_json::to_value(key.public_jwk())?)
        .bind(encrypted).execute(&state.db_pool).await.map_err(|_| "managed encryption key fixture insert failed")?;
    reload_authorization_runtime(state).await
}

struct KeyEnvironment(Option<std::ffi::OsString>);
impl KeyEnvironment {
    fn install() -> Self {
        let previous = std::env::var_os(crate::key_encryption::KEY_ENCRYPTION_KEY_ENV);
        std::env::set_var(
            crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
            URL_SAFE_NO_PAD.encode(FIXTURE_KEK),
        );
        Self(previous)
    }
}
impl Drop for KeyEnvironment {
    fn drop(&mut self) {
        if let Some(value) = &self.0 {
            std::env::set_var(crate::key_encryption::KEY_ENCRYPTION_KEY_ENV, value);
        } else {
            std::env::remove_var(crate::key_encryption::KEY_ENCRYPTION_KEY_ENV);
        }
    }
}

pub(crate) async fn derive_test_authorization_runtime(
    loaded: DatabaseRuntimeConfiguration,
    baseline: ServerConfig,
) -> TestResult<AuthorizationRuntime> {
    // Existing key tests use this same lock. Keep the lock off the async worker
    // so concurrent fixtures cannot block a runtime needed by its current owner.
    Ok(
        tokio::task::spawn_blocking(move || -> anyhow::Result<AuthorizationRuntime> {
            let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
                .lock()
                .map_err(|error| io::Error::other(error.to_string()))?;
            let _env = KeyEnvironment::install();
            tokio::runtime::Handle::current()
                .block_on(loaded.derive_authorization_runtime(baseline))
        })
        .await??,
    )
}

pub(crate) async fn reload_authorization_runtime(state: &mut AppState) -> TestResult {
    let loaded = crate::runtime_configuration::load_database_runtime_configuration(
        &state.db_pool,
        state.runtime_authority.issuer_host(),
    )
    .await?;
    let derived = derive_test_authorization_runtime(loaded, (*state.cfg).clone()).await?;
    state.cfg = derived.configuration();
    state.oidc.config = derived.oidc();
    state.runtime_authority =
        crate::web::RuntimeAuthorityState::from_authorization_runtime(derived);
    Ok(())
}

pub(crate) async fn update_test_policy(
    state: &mut AppState,
    update: impl FnOnce(&mut PolicyDocument),
) -> TestResult {
    let mut document: serde_json::Value = sqlx::query_scalar(
        "SELECT configuration_document FROM aegaeon.active_runtime_environments WHERE environment_id=$1",
    ).bind(state.environment_id).fetch_one(&state.db_pool).await?;
    let mut policy: PolicyDocument = serde_json::from_value(document["policy"].clone())?;
    update(&mut policy);
    document["policy"] = serde_json::to_value(policy)?;
    sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document=$1 WHERE environment_id=$2 AND status='ACTIVE'")
        .bind(document).bind(state.environment_id).execute(&state.db_pool).await?;
    reload_authorization_runtime(state).await
}
