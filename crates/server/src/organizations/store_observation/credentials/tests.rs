use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

struct KeyEnvironment(Option<std::ffi::OsString>);
impl KeyEnvironment {
    fn new() -> Self {
        let previous = std::env::var_os(crate::key_encryption::KEY_ENCRYPTION_KEY_ENV);
        std::env::set_var(
            crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
            URL_SAFE_NO_PAD.encode([71u8; 32]),
        );
        Self(previous)
    }
}
impl Drop for KeyEnvironment {
    fn drop(&mut self) {
        let name = crate::key_encryption::KEY_ENCRYPTION_KEY_ENV;
        match &self.0 {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
}

#[test]
fn restored_password_profile_rejects_unknown_cost_and_encoding() -> Result<()> {
    let hash = crate::local_credentials::hash_password("retained-original-password")
        .map_err(anyhow::Error::msg)?;
    password_profile(&hash)?;
    for bad in [
        hash.replace("m=19456", "m=1048576"),
        hash.replace("argon2id", "argon2i"),
        hash.replace("v=19", "v=16"),
        "invalid".into(),
    ] {
        assert!(password_profile(&bad).is_err());
    }
    let mut pieces: Vec<String> = hash.split('$').map(str::to_owned).collect();
    pieces[4].pop();
    pieces[4].push('B'); // Four unused salt bits must not hide a different encoding.
    assert!(password_profile(&pieces.join("$")).is_err());
    assert!(crate::local_credentials::verify_password(
        "retained-original-password",
        &hash
    ));
    Ok(())
}

#[test]
fn restored_key_uses_serving_decryptor_and_public_key_check() -> Result<()> {
    use crate::runtime_keys::*;
    let _lock = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock().unwrap();
    let _environment = KeyEnvironment::new();
    let der = pem::parse(include_str!(
        "../../../../tests/fixtures/rsa2048-private.pk8.pem"
    ))?;
    let signing =
        crate::oidc::OidcSigningKey::from_rsa_pkcs8_der("restored".into(), der.contents())?;
    let mut key = RuntimeKey {
        environment_id: Uuid::new_v4(),
        usage: RuntimeKeyUsage::OidcIdTokenSigning,
        algorithm: RuntimeKeyAlgorithm::Rs256,
        provider: RuntimeKeyProvider::DatabaseEncrypted,
        status: RuntimeKeyStatus::Active,
        retiring_expires_at_epoch_secs: None,
        kid: "restored".into(),
        public_jwk: signing.jwks().keys.remove(0),
        key_handle: String::new(),
        provider_configuration: json!({}),
    };
    key.key_handle = crate::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(der.contents()),
        &[71; 32],
        key.key_handle_encryption_context(),
    )?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(crate::oidc::config::validate_restored_oidc_key(&key))?;
    let mut bad = key.clone();
    bad.environment_id = Uuid::new_v4();
    assert!(runtime
        .block_on(crate::oidc::config::validate_restored_oidc_key(&bad))
        .is_err());
    let mut bad = key.clone();
    bad.public_jwk.n = Some("AQAB".into());
    assert!(runtime
        .block_on(crate::oidc::config::validate_restored_oidc_key(&bad))
        .is_err());
    std::env::set_var(
        crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
        URL_SAFE_NO_PAD.encode([72u8; 32]),
    );
    assert!(runtime
        .block_on(crate::oidc::config::validate_restored_oidc_key(&key))
        .is_err());
    Ok(())
}

#[test]
#[ignore = "requires isolated PostgreSQL with current schema and runtime role"]
fn pg_restored_credentials_readonly_and_wrong_key_refused() -> Result<()> {
    let _lock = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock().unwrap();
    let _environment = KeyEnvironment::new();
    tokio::runtime::Runtime::new()?.block_on(database())
}

async fn database() -> Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = crate::web::test_support::setup_test_environment(&pool).await?;
    let mut connection = pool.acquire().await?;
    crate::web::namespace_runtime::validate_connection_inputs(
        &mut connection,
        env.environment_id,
        &env.issuer_url,
    )
    .await?;
    let empty = inspect_connection(&mut connection, env.environment_id).await?;
    assert_eq!(empty["upstreamSecretsDecrypted"], 0);
    let id = Uuid::new_v4();
    let sealed = crate::upstream::seal_upstream_client_secret(
        "retained-private-secret",
        env.environment_id,
        id,
    )
    .map_err(|_| anyhow::anyhow!("fixture encryption"))?;
    sqlx::query("INSERT INTO aegaeon.connections(id,environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,client_secret_encrypted) SELECT $1,id,active_configuration_version_id,'restore-connection','Restore','https://upstream.example','client',$3 FROM aegaeon.environments WHERE id=$2")
        .bind(id).bind(env.environment_id).bind(&sealed).execute(&mut *connection).await?;
    let result = inspect_connection(&mut connection, env.environment_id).await?;
    assert_eq!(result["upstreamSecretsDecrypted"], 1);
    assert_eq!(result["passwordKnowledgeChecked"], false);
    let user = Uuid::new_v4();
    let hash = crate::local_credentials::hash_password("retained-original-password")
        .map_err(anyhow::Error::msg)?;
    sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,'restored-owner','ACTIVE')")
        .bind(user).bind(env.environment_id).execute(&mut *connection).await?;
    sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash) VALUES($1,$2)")
        .bind(user).bind(&hash).execute(&mut *connection).await?;
    let result = inspect_connection(&mut connection, env.environment_id).await?;
    assert_eq!(result["localPasswordProfiles"], 1);
    sqlx::query(
        "UPDATE aegaeon.end_user_password_credentials SET password_hash=$2 WHERE end_user_id=$1",
    )
    .bind(user)
    .bind(hash.replace("m=19456", "m=1048576"))
    .execute(&mut *connection)
    .await?;
    assert!(inspect_connection(&mut connection, env.environment_id)
        .await
        .is_err());
    sqlx::query(
        "UPDATE aegaeon.end_user_password_credentials SET password_hash=$2 WHERE end_user_id=$1",
    )
    .bind(user)
    .bind(&hash)
    .execute(&mut *connection)
    .await?;
    sqlx::query("UPDATE aegaeon.connections SET client_secret_encrypted=$2 WHERE id=$1")
        .bind(id)
        .bind(vec![b'x'; MAX_CELL as usize + 1])
        .execute(&mut *connection)
        .await?;
    assert!(inspect_connection(&mut connection, env.environment_id)
        .await
        .unwrap_err()
        .to_string()
        .contains("budget"));
    sqlx::query("UPDATE aegaeon.connections SET client_secret_encrypted=$2 WHERE id=$1")
        .bind(id)
        .bind(&sealed)
        .execute(&mut *connection)
        .await?;
    std::env::set_var(
        crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
        URL_SAFE_NO_PAD.encode([72u8; 32]),
    );
    assert!(inspect_connection(&mut connection, env.environment_id)
        .await
        .is_err());
    std::env::set_var(
        crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
        URL_SAFE_NO_PAD.encode([71u8; 32]),
    );
    inspect_connection(&mut connection, env.environment_id).await?;
    let retained: Vec<u8> =
        sqlx::query_scalar("SELECT client_secret_encrypted FROM aegaeon.connections WHERE id=$1")
            .bind(id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(retained, sealed);
    // The namespace checker must reject a foreign issuer before any credential check.
    assert!(crate::web::namespace_runtime::validate_connection_inputs(
        &mut connection,
        env.environment_id,
        "https://foreign.example"
    )
    .await
    .is_err());
    connection.close().await?;
    pool.close().await;
    Ok(())
}
