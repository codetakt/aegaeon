
// ---------------------------------------------------------------
// M-5: Key encryption at rest tests
// ---------------------------------------------------------------

fn key_handle_test_environment_id() -> uuid::Uuid {
    uuid::Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888)
}

fn key_handle_test_context(kid: &str) -> KeyHandleEncryptionContext<'_> {
    KeyHandleEncryptionContext::new(
        key_handle_test_environment_id(),
        "OIDC_ID_TOKEN_SIGNING",
        "databaseEncrypted",
        "RS256",
        kid,
    )
}

#[test]
fn load_key_encryption_key_accepts_valid_base64url_32_byte_key() -> TestResult {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "key encryption key env guard".to_string())?;
    let encoded = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
    let _env = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, encoded);

    assert_eq!(load_key_encryption_key(), Ok([0x42u8; 32]));
    Ok(())
}

#[test]
fn load_key_encryption_key_distinguishes_missing_and_malformed_values() -> TestResult {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "key encryption key env guard".to_string())?;

    let _env = EnvVarGuard::unset(KEY_ENCRYPTION_KEY_ENV);
    assert_eq!(
        load_key_encryption_key(),
        Err(KeyEncryptionKeyLoadError::Missing)
    );

    std::env::set_var(KEY_ENCRYPTION_KEY_ENV, "   ");
    assert_eq!(
        load_key_encryption_key(),
        Err(KeyEncryptionKeyLoadError::Empty)
    );

    std::env::set_var(KEY_ENCRYPTION_KEY_ENV, "not base64url!");
    assert_eq!(
        load_key_encryption_key(),
        Err(KeyEncryptionKeyLoadError::InvalidEncoding)
    );

    let encoded_short = URL_SAFE_NO_PAD.encode([0x42u8; 31]);
    std::env::set_var(KEY_ENCRYPTION_KEY_ENV, encoded_short);
    assert_eq!(
        load_key_encryption_key(),
        Err(KeyEncryptionKeyLoadError::InvalidLength(31))
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn load_key_encryption_key_rejects_non_unicode_values() -> TestResult {
    use std::os::unix::ffi::OsStringExt;

    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "key encryption key env guard".to_string())?;
    let _env = EnvVarGuard::set(
        KEY_ENCRYPTION_KEY_ENV,
        OsString::from_vec(vec![0x41, 0x80, 0x42]),
    );

    assert_eq!(
        load_key_encryption_key(),
        Err(KeyEncryptionKeyLoadError::NonUnicode)
    );
    Ok(())
}

#[test]
fn encrypt_decrypt_key_handle_roundtrip() -> TestResult {
    let kek = [0x42u8; 32]; // test key
    let plaintext = "test_pkcs8_private_key_material_base64url_encoded";
    let context = key_handle_test_context("runtime-key-1");
    let Ok(encrypted) = encrypt_key_handle(plaintext, &kek, context) else {
        return Err(io::Error::other("encryption failed").into());
    };
    assert!(encrypted.starts_with(KEY_HANDLE_ENVELOPE_PREFIX));
    assert_ne!(
        encrypted, plaintext,
        "encrypted should differ from plaintext"
    );
    let Ok(decrypted) = decrypt_key_handle(&encrypted, &kek, context) else {
        return Err(io::Error::other("decryption failed").into());
    };
    assert_eq!(decrypted, plaintext, "roundtrip should preserve plaintext");
    Ok(())
}

#[test]
fn encrypt_key_handle_produces_different_ciphertext_each_time() -> TestResult {
    let kek = [0x42u8; 32];
    let plaintext = "some_key_material";
    let context = key_handle_test_context("runtime-key-1");
    let Ok(e1) = encrypt_key_handle(plaintext, &kek, context) else {
        return Err(io::Error::other("first encryption failed").into());
    };
    let Ok(e2) = encrypt_key_handle(plaintext, &kek, context) else {
        return Err(io::Error::other("second encryption failed").into());
    };
    assert_ne!(
        e1, e2,
        "different nonces should produce different ciphertexts"
    );
    // Both should decrypt correctly
    let Ok(d1) = decrypt_key_handle(&e1, &kek, context) else {
        return Err(io::Error::other("first decrypt failed").into());
    };
    let Ok(d2) = decrypt_key_handle(&e2, &kek, context) else {
        return Err(io::Error::other("second decrypt failed").into());
    };
    assert_eq!(d1, plaintext);
    assert_eq!(d2, plaintext);
    Ok(())
}

#[test]
fn decrypt_key_handle_wrong_key_fails() -> TestResult {
    let kek1 = [0x42u8; 32];
    let kek2 = [0x43u8; 32]; // different key
    let plaintext = "sensitive_key_material";
    let context = key_handle_test_context("runtime-key-1");
    let Ok(encrypted) = encrypt_key_handle(plaintext, &kek1, context) else {
        return Err(io::Error::other("encryption failed").into());
    };
    let result = decrypt_key_handle(&encrypted, &kek2, context);
    assert!(result.is_err(), "wrong key should fail decryption");
    Ok(())
}

#[test]
fn decrypt_key_handle_wrong_context_fails() -> TestResult {
    let kek = [0x42u8; 32];
    let plaintext = "sensitive_key_material";
    let context = key_handle_test_context("runtime-key-1");
    let encrypted = encrypt_key_handle(plaintext, &kek, context)?;

    let result = decrypt_key_handle(&encrypted, &kek, key_handle_test_context("runtime-key-2"));

    assert!(result.is_err(), "wrong AAD context should fail decryption");
    Ok(())
}

#[test]
fn decrypt_key_handle_tampered_ciphertext_fails() -> TestResult {
    let kek = [0x42u8; 32];
    let plaintext = "key_material_to_tamper";
    let context = key_handle_test_context("runtime-key-1");
    let Ok(encrypted) = encrypt_key_handle(plaintext, &kek, context) else {
        return Err(io::Error::other("encryption failed").into());
    };
    let encoded = encrypted
        .strip_prefix(KEY_HANDLE_ENVELOPE_PREFIX)
        .ok_or_else(|| io::Error::other("missing envelope prefix"))?;
    let mut data = URL_SAFE_NO_PAD.decode(encoded)?;
    // Flip a byte in the ciphertext (after the 12-byte nonce)
    if data.len() > 13 {
        data[13] ^= 0xFF;
    }
    let tampered = format!("{}{}", KEY_HANDLE_ENVELOPE_PREFIX, URL_SAFE_NO_PAD.encode(&data));
    let result = decrypt_key_handle(&tampered, &kek, context);
    assert!(result.is_err(), "tampered ciphertext should fail");
    Ok(())
}

#[test]
fn decrypt_key_handle_too_short_fails() {
    let kek = [0x42u8; 32];
    let short = format!(
        "{}{}",
        KEY_HANDLE_ENVELOPE_PREFIX,
        URL_SAFE_NO_PAD.encode([0u8; 10])
    ); // too short (< 12 + 16)
    let result = decrypt_key_handle(&short, &kek, key_handle_test_context("runtime-key-1"));
    assert!(result.is_err(), "too-short data should fail");
}
