// ── Secret redaction tests ─────────────────────────────────────────

#[test]
fn redact_json_value_strips_client_secret() {
    let mut val = serde_json::json!({
        "client_id": "abc",
        "client_secret": "super-secret",
        "client_secret_expires_at": 123_456
    });
    redact_json_value(&mut val);
    assert_eq!(val["client_id"], "abc");
    assert_eq!(val["client_secret"], "[REDACTED]");
    assert_eq!(val["client_secret_expires_at"], "[REDACTED]");
}

#[test]
fn redact_json_value_strips_password() {
    let mut val = serde_json::json!({
        "username": "user1",
        "password": "p@ss",
        "password_hash": "sha256:..."
    });
    redact_json_value(&mut val);
    assert_eq!(val["username"], "user1");
    assert_eq!(val["password"], "[REDACTED]");
    assert_eq!(val["password_hash"], "[REDACTED]");
}

#[test]
fn redact_json_value_strips_encrypted_fields() {
    let mut val = serde_json::json!({
        "data_encrypted": "aes-ciphertext",
        "normal_field": "visible"
    });
    redact_json_value(&mut val);
    assert_eq!(val["data_encrypted"], "[REDACTED]");
    assert_eq!(val["normal_field"], "visible");
}

#[test]
fn redact_json_value_strips_key_handle() {
    let mut val = serde_json::json!({
        "key_handle": "handle-123",
        "key_id": "kid-456"
    });
    redact_json_value(&mut val);
    assert_eq!(val["key_handle"], "[REDACTED]");
    assert_eq!(val["key_id"], "kid-456");
}

#[test]
fn redact_json_value_handles_nested_objects() {
    let mut val = serde_json::json!({
        "outer": {
            "client_secret": "nested-secret",
            "safe": "ok"
        }
    });
    redact_json_value(&mut val);
    assert_eq!(val["outer"]["client_secret"], "[REDACTED]");
    assert_eq!(val["outer"]["safe"], "ok");
}

#[test]
fn redact_json_value_handles_arrays() {
    let mut val = serde_json::json!([
        {"password": "s1", "name": "a"},
        {"secret_key": "s2", "name": "b"}
    ]);
    redact_json_value(&mut val);
    assert_eq!(val[0]["password"], "[REDACTED]");
    assert_eq!(val[0]["name"], "a");
    assert_eq!(val[1]["secret_key"], "[REDACTED]");
    assert_eq!(val[1]["name"], "b");
}

#[test]
fn redact_json_value_redacts_one_time_secret_fields() {
    let mut val = serde_json::json!({
        "accessToken": "access-token",
        "actorToken": "actor-token",
        "assertion": "jwt-bearer-assertion",
        "authorizationCode": "authorization-code",
        "bootstrapToken": "bootstrap-secret",
        "clientAssertion": "private-key-jwt",
        "codeVerifier": "pkce-secret",
        "csrfToken": "csrf-secret",
        "deviceCode": "device-code",
        "idToken": "id-token",
        "token": "raw-token",
        "tokenId": "safe-id",
        "activationTokenId": "safe-activation-id",
        "redeemUrl": "https://issuer.example/auth/activate?token=raw-token",
        "apiKeyValue": "aeg_raw-key",
        "refreshToken": "refresh-token",
        "registrationAccessToken": "rat-secret",
        "request": "signed-request-object",
        "subjectToken": "subject-token",
        "privateKeyPem": "pkcs8-secret",
        "userCode": "ABCD-EFGH",
        "keyPrefix": "aeg_prefix"
    });
    redact_json_value(&mut val);
    assert_eq!(val["accessToken"], "[REDACTED]");
    assert_eq!(val["actorToken"], "[REDACTED]");
    assert_eq!(val["assertion"], "[REDACTED]");
    assert_eq!(val["authorizationCode"], "[REDACTED]");
    assert_eq!(val["bootstrapToken"], "[REDACTED]");
    assert_eq!(val["clientAssertion"], "[REDACTED]");
    assert_eq!(val["codeVerifier"], "[REDACTED]");
    assert_eq!(val["csrfToken"], "[REDACTED]");
    assert_eq!(val["deviceCode"], "[REDACTED]");
    assert_eq!(val["idToken"], "[REDACTED]");
    assert_eq!(val["token"], "[REDACTED]");
    assert_eq!(val["tokenId"], "safe-id");
    assert_eq!(val["activationTokenId"], "safe-activation-id");
    assert_eq!(val["redeemUrl"], "[REDACTED]");
    assert_eq!(val["apiKeyValue"], "[REDACTED]");
    assert_eq!(val["refreshToken"], "[REDACTED]");
    assert_eq!(val["registrationAccessToken"], "[REDACTED]");
    assert_eq!(val["request"], "[REDACTED]");
    assert_eq!(val["subjectToken"], "[REDACTED]");
    assert_eq!(val["privateKeyPem"], "[REDACTED]");
    assert_eq!(val["userCode"], "[REDACTED]");
    assert_eq!(val["keyPrefix"], "aeg_prefix");
}

#[test]
fn redact_json_value_no_secrets_is_noop() {
    let mut val = serde_json::json!({
        "event_type": "TOKEN_ISSUED",
        "client_id": "abc-123",
        "scope": "openid profile"
    });
    let original = val.clone();
    redact_json_value(&mut val);
    assert_eq!(val, original);
}

#[test]
fn redact_audit_event_applies_to_both_fields() -> TestResult {
    let mut event = AuditEvent {
        id: "00000000-0000-0000-0000-000000000001".to_string(),
        team_id: "00000000-0000-0000-0000-000000000002".to_string(),
        tenant_id: None,
        environment_id: None,
        event_type: "CLIENT_UPDATED".to_string(),
        category: "MANAGEMENT".to_string(),
        outcome: "SUCCESS".to_string(),
        severity: "MEDIUM".to_string(),
        occurred_at: "2026-01-15T10:00:00Z".to_string(),
        actor: AuditActor {
            actor_type: "USER".to_string(),
            actor_id: Some("user-1".to_string()),
            ip_address: None,
            user_agent: None,
            mfa: None,
        },
        target: AuditTarget {
            target_type: "CLIENT".to_string(),
            target_id: Some("client-1".to_string()),
        },
        request: AuditRequestContext {
            request_id: "req-1".to_string(),
            trace_id: None,
            span_id: None,
        },
        change: Some(AuditChange {
            from_configuration_version_id: None,
            to_configuration_version_id: None,
            json_patch: Some(serde_json::json!({
                "client_secret": "old-secret",
                "redirect_uris": ["https://example.com"]
            })),
        }),
        data: Some(serde_json::json!({
            "password_hash": "sha256:abc",
            "display_name": "My Client"
        })),
    };
    redact_audit_event(&mut event);
    let patch = event
        .change
        .as_ref()
        .and_then(|change| change.json_patch.as_ref())
        .ok_or_else(|| io::Error::other("missing audit patch"))?;
    assert_eq!(patch["client_secret"], "[REDACTED]");
    assert_eq!(
        patch["redirect_uris"],
        serde_json::json!(["https://example.com"])
    );
    let data = event
        .data
        .as_ref()
        .ok_or_else(|| io::Error::other("missing audit data"))?;
    assert_eq!(data["password_hash"], "[REDACTED]");
    assert_eq!(data["display_name"], "My Client");
    Ok(())
}

#[test]
fn dcr_bearer_token_validation_rejects_empty_or_weak_tokens() {
    assert!(validate_dcr_bearer_token("", "req").is_err());
    assert!(validate_dcr_bearer_token("   ", "req").is_err());
    assert!(validate_dcr_bearer_token("short-registration-gate", "req").is_err());
}

#[test]
fn dcr_bearer_token_validation_trims_and_accepts_32_bytes() -> TestResult {
    let token = "0123456789abcdef0123456789abcdef";
    let raw = format!(" {token}\n");

    let validated = validate_dcr_bearer_token(&raw, "req")
        .map_err(|_| io::Error::other("strong token rejected"))?;

    assert_eq!(validated, token);
    Ok(())
}

#[test]
fn audit_max_range_seconds_is_90_days() {
    assert_eq!(AUDIT_MAX_RANGE_SECONDS, 90 * 24 * 3600);
}
