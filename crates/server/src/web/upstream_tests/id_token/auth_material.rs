use super::*;

#[test]
fn upstream_authorize_auth_material_validates_connection_secret_envelope() -> TestResult {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "key encryption key env guard".to_string())?;
    let key = URL_SAFE_NO_PAD.encode([0x54u8; 32]);
    let _env = EnvVarGuard::new(
        crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
        Some(key.as_str()),
    );
    let environment_id = uuid::Uuid::new_v4();
    let connection_id = uuid::Uuid::new_v4();
    let sealed = crate::upstream::seal_upstream_client_secret(
        "upstream-client-secret",
        environment_id,
        connection_id,
    )
    .map_err(|err| format!("seal client secret: {err:?}"))?;
    let connection = test_upstream_connection(
        environment_id,
        connection_id,
        "client_secret_basic",
        Some(sealed),
    );

    let method = upstream_authorize_auth_material(&connection, "https://issuer.example")
        .map_err(|_| "connection secret should decrypt".to_string())?;

    assert_eq!(method, "client_secret_basic");
    Ok(())
}

#[test]
fn upstream_authorize_auth_material_rejects_plaintext_connection_secret() -> TestResult {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "key encryption key env guard".to_string())?;
    let key = URL_SAFE_NO_PAD.encode([0x55u8; 32]);
    let _env = EnvVarGuard::new(
        crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
        Some(key.as_str()),
    );
    let connection = test_upstream_connection(
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        "client_secret_post",
        Some(b"legacy-plaintext-secret".to_vec()),
    );

    assert!(upstream_authorize_auth_material(&connection, "https://issuer.example").is_err());
    Ok(())
}
