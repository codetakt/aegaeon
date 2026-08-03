use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[test]
fn upstream_client_secret_envelope_round_trips_without_plaintext() {
    let _guard = must_ok(crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock());
    let key = URL_SAFE_NO_PAD.encode([0x51u8; 32]);
    let _env = EnvVarGuard::new(super::KEY_ENCRYPTION_KEY_ENV, Some(key.as_str()));
    let environment_id = uuid::Uuid::new_v4();
    let connection_id = uuid::Uuid::new_v4();
    let client_secret = "opaque-password-value";

    let sealed = must_ok(super::seal_upstream_client_secret(
        client_secret,
        environment_id,
        connection_id,
    ));
    let envelope = must_ok(std::str::from_utf8(sealed.as_slice()));

    assert!(envelope.starts_with(super::UPSTREAM_CLIENT_SECRET_ENVELOPE_PREFIX));
    assert!(!envelope.contains(client_secret));
    assert_eq!(
        must_ok(super::open_upstream_client_secret(
            sealed.as_slice(),
            environment_id,
            connection_id
        )),
        client_secret
    );
}

#[test]
fn upstream_client_secret_envelope_binds_connection_context() {
    let _guard = must_ok(crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock());
    let key = URL_SAFE_NO_PAD.encode([0x52u8; 32]);
    let _env = EnvVarGuard::new(super::KEY_ENCRYPTION_KEY_ENV, Some(key.as_str()));
    let environment_id = uuid::Uuid::new_v4();
    let connection_id = uuid::Uuid::new_v4();
    let sealed = must_ok(super::seal_upstream_client_secret(
        "upstream-client-secret",
        environment_id,
        connection_id,
    ));

    let err = must_err(super::open_upstream_client_secret(
        sealed.as_slice(),
        environment_id,
        uuid::Uuid::new_v4(),
    ));

    assert_eq!(
        err,
        super::UpstreamClientSecretEnvelopeError::DecryptionFailed
    );
}

#[test]
fn upstream_client_secret_envelope_rejects_plaintext_legacy_value() {
    let _guard = must_ok(crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock());
    let key = URL_SAFE_NO_PAD.encode([0x53u8; 32]);
    let _env = EnvVarGuard::new(super::KEY_ENCRYPTION_KEY_ENV, Some(key.as_str()));

    let err = must_err(super::open_upstream_client_secret(
        b"legacy-plaintext-secret",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    ));

    assert_eq!(
        err,
        super::UpstreamClientSecretEnvelopeError::EnvelopeInvalid
    );
}

#[test]
fn upstream_client_auth_method_secret_classification_is_exact() {
    assert!(super::upstream_client_auth_method_uses_secret(
        " client_secret_basic "
    ));
    assert!(super::upstream_client_auth_method_uses_secret(
        "CLIENT_SECRET_POST"
    ));
    assert!(!super::upstream_client_auth_method_uses_secret("none"));
    assert!(!super::upstream_client_auth_method_uses_secret(
        "private_key_jwt"
    ));
}

#[test]
fn upstream_client_auth_method_support_is_runtime_exact() {
    assert!(super::upstream_client_auth_method_supported(
        " client_secret_basic "
    ));
    assert!(super::upstream_client_auth_method_supported(
        "CLIENT_SECRET_POST"
    ));
    assert!(super::upstream_client_auth_method_supported("none"));
    assert!(!super::upstream_client_auth_method_supported(
        "private_key_jwt"
    ));
    assert!(!super::upstream_client_auth_method_supported("mtls"));
}
