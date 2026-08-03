
#[test]
fn parse_local_login_submission_requires_valid_single_use_csrf() -> TestResult {
    let store = CsrfTokenStore::new_process_local_for_tests();
    let without_csrf = vec![
        ("identifier".to_string(), "user@example.com".to_string()),
        ("password".to_string(), "correct horse".to_string()),
    ];
    let err = require_err(
        parse_local_login_submission(
            &HeaderMap::new(),
            Ok(axum::extract::Form(without_csrf)),
            &store,
        ),
        "missing csrf token must be rejected",
    )?;
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);

    let csrf_token = store.generate();
    let with_csrf = vec![
        ("return_to".to_string(), "/continue".to_string()),
        ("acr".to_string(), "urn:pwd".to_string()),
        ("identifier".to_string(), "user@example.com".to_string()),
        ("password".to_string(), "correct horse".to_string()),
        ("csrf_token".to_string(), csrf_token.clone()),
    ];
    let missing_cookie = require_err(
        parse_local_login_submission(
            &HeaderMap::new(),
            Ok(axum::extract::Form(with_csrf.clone())),
            &store,
        ),
        "csrf token without matching cookie must be rejected",
    )?;
    assert_eq!(missing_cookie.status(), StatusCode::BAD_REQUEST);

    let headers = headers_with_csrf_cookie(LOCAL_AUTH_CSRF_COOKIE_NAME, &csrf_token)?;
    let submission =
        parse_local_login_submission(&headers, Ok(axum::extract::Form(with_csrf.clone())), &store)
            .map_err(|response| format!("expected accepted form: {}", response.status()))?;
    assert_eq!(submission.return_to.as_deref(), Some("/continue"));
    assert_eq!(submission.requested_acr.as_deref(), Some("urn:pwd"));
    assert_eq!(submission.identifier, "user@example.com");

    let replay = require_err(
        parse_local_login_submission(&headers, Ok(axum::extract::Form(with_csrf)), &store),
        "csrf token replay must be rejected",
    )?;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[test]
fn parse_local_login_submission_reports_csrf_store_outage() -> TestResult {
    let _guard = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|err| err.to_string())?;
    let _env = EnvVarGuard::new(
        "AEGAEON_TEST_LOCAL_LOGIN_CSRF_REDIS_URL",
        Some("redis://127.0.0.1:1/"),
    );
    let store = CsrfTokenStore::try_from_shared_store_env(
        "AEGAEON_TEST_LOCAL_LOGIN_CSRF_REDIS_URL",
        "test-local-login",
        &crate::config::RuntimeStateNamespace::for_tests("local-login-csrf-test"),
    )
    .map_err(|err| err.to_string())?;
    let csrf_token = "csrf-token";
    let headers = headers_with_csrf_cookie(LOCAL_AUTH_CSRF_COOKIE_NAME, csrf_token)?;
    let params = vec![
        ("identifier".to_string(), "user@example.com".to_string()),
        ("password".to_string(), "correct horse".to_string()),
        ("csrf_token".to_string(), csrf_token.to_string()),
    ];

    let err = require_err(
        parse_local_login_submission(&headers, Ok(axum::extract::Form(params)), &store),
        "CSRF store outage must surface as service unavailable",
    )?;
    assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

#[test]
fn parse_local_login_submission_rejects_duplicate_singleton_fields() -> TestResult {
    for field in ["return_to", "acr", "csrf_token", "identifier", "password"] {
        let store = CsrfTokenStore::new_process_local_for_tests();
        let csrf_token = store.generate();
        let headers = headers_with_csrf_cookie(LOCAL_AUTH_CSRF_COOKIE_NAME, &csrf_token)?;
        let valid_shape = vec![
            ("return_to".to_string(), "/continue".to_string()),
            ("acr".to_string(), "urn:pwd".to_string()),
            ("identifier".to_string(), "user@example.com".to_string()),
            ("password".to_string(), "correct horse".to_string()),
            ("csrf_token".to_string(), csrf_token.clone()),
        ];
        let duplicate_value = match field {
            "return_to" => "/other".to_string(),
            "acr" => "urn:other".to_string(),
            "csrf_token" => csrf_token.clone(),
            "identifier" => "other@example.com".to_string(),
            "password" => "different horse".to_string(),
            _ => return Err(format!("unhandled duplicate login field: {field}")),
        };
        let mut duplicated = valid_shape.clone();
        duplicated.push((field.to_string(), duplicate_value));

        let err = require_err(
            parse_local_login_submission(&headers, Ok(axum::extract::Form(duplicated)), &store),
            "duplicate singleton form field must be rejected",
        )?;
        assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{field}");

        parse_local_login_submission(&headers, Ok(axum::extract::Form(valid_shape)), &store)
            .map_err(|response| {
                format!(
                    "duplicate {field} consumed csrf unexpectedly: {}",
                    response.status()
                )
            })?;
    }
    Ok(())
}

#[test]
fn local_login_audit_data_omits_submitted_identifier() -> TestResult {
    let email = "user@example.com";
    let failure = local_login_failure_audit_data(email);
    let success = local_login_success_audit_data(email);

    assert_eq!(failure["identifierKind"], "email");
    assert_eq!(failure["reason"], "invalid_credentials");
    assert_eq!(success["identifierKind"], "email");

    let failure_text = serde_json::to_string(&failure).map_err(|err| err.to_string())?;
    let success_text = serde_json::to_string(&success).map_err(|err| err.to_string())?;
    assert!(!failure_text.contains(email));
    assert!(!success_text.contains(email));
    assert!(failure.get("identifier").is_none());
    assert!(success.get("identifier").is_none());

    let subject = "subject-1234";
    let subject_failure = local_login_failure_audit_data(subject);
    assert_eq!(subject_failure["identifierKind"], "subject");
    let subject_failure_text =
        serde_json::to_string(&subject_failure).map_err(|err| err.to_string())?;
    assert!(!subject_failure_text.contains(subject));
    Ok(())
}

#[test]
fn parse_local_recovery_submission_requires_valid_single_use_csrf() -> TestResult {
    let store = CsrfTokenStore::new_process_local_for_tests();
    let without_csrf = vec![
        ("token".to_string(), "activation-token".to_string()),
        ("password".to_string(), "short".to_string()),
        ("password_confirmation".to_string(), "different".to_string()),
    ];
    let err = require_err(
        parse_local_recovery_submission(
            &HeaderMap::new(),
            Ok(axum::extract::Form(without_csrf)),
            RecoveryTokenPurpose::Activation,
            &store,
        ),
        "missing csrf token must be rejected before password validation",
    )?;
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);

    let csrf_token = store.generate();
    let valid_shape = vec![
        ("token".to_string(), "activation-token".to_string()),
        ("password".to_string(), "long-enough-password".to_string()),
        (
            "password_confirmation".to_string(),
            "long-enough-password".to_string(),
        ),
        ("csrf_token".to_string(), csrf_token.clone()),
    ];
    let missing_cookie = require_err(
        parse_local_recovery_submission(
            &HeaderMap::new(),
            Ok(axum::extract::Form(valid_shape.clone())),
            RecoveryTokenPurpose::Activation,
            &store,
        ),
        "csrf token without matching cookie must be rejected",
    )?;
    assert_eq!(missing_cookie.status(), StatusCode::BAD_REQUEST);

    let headers = headers_with_csrf_cookie(LOCAL_AUTH_CSRF_COOKIE_NAME, &csrf_token)?;
    parse_local_recovery_submission(
        &headers,
        Ok(axum::extract::Form(valid_shape.clone())),
        RecoveryTokenPurpose::Activation,
        &store,
    )
    .map_err(|response| format!("expected accepted recovery form: {}", response.status()))?;

    let replay = require_err(
        parse_local_recovery_submission(
            &headers,
            Ok(axum::extract::Form(valid_shape)),
            RecoveryTokenPurpose::Activation,
            &store,
        ),
        "csrf token replay must be rejected",
    )?;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[test]
fn parse_local_recovery_submission_reports_csrf_store_outage() -> TestResult {
    let _guard = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|err| err.to_string())?;
    let _env = EnvVarGuard::new(
        "AEGAEON_TEST_LOCAL_RECOVERY_CSRF_REDIS_URL",
        Some("redis://127.0.0.1:1/"),
    );
    let store = CsrfTokenStore::try_from_shared_store_env(
        "AEGAEON_TEST_LOCAL_RECOVERY_CSRF_REDIS_URL",
        "test-local-recovery",
        &crate::config::RuntimeStateNamespace::for_tests("local-recovery-csrf-test"),
    )
    .map_err(|err| err.to_string())?;
    let csrf_token = "csrf-token";
    let headers = headers_with_csrf_cookie(LOCAL_AUTH_CSRF_COOKIE_NAME, csrf_token)?;
    let params = vec![
        ("token".to_string(), "activation-token".to_string()),
        ("password".to_string(), "long-enough-password".to_string()),
        (
            "password_confirmation".to_string(),
            "long-enough-password".to_string(),
        ),
        ("csrf_token".to_string(), csrf_token.to_string()),
    ];

    let err = require_err(
        parse_local_recovery_submission(
            &headers,
            Ok(axum::extract::Form(params)),
            RecoveryTokenPurpose::Activation,
            &store,
        ),
        "CSRF store outage must surface as service unavailable",
    )?;
    assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

#[test]
fn parse_local_recovery_submission_rejects_duplicate_singleton_fields() -> TestResult {
    for field in [
        "return_to",
        "token",
        "csrf_token",
        "password",
        "password_confirmation",
    ] {
        let store = CsrfTokenStore::new_process_local_for_tests();
        let csrf_token = store.generate();
        let headers = headers_with_csrf_cookie(LOCAL_AUTH_CSRF_COOKIE_NAME, &csrf_token)?;
        let valid_shape = vec![
            ("return_to".to_string(), "/continue".to_string()),
            ("token".to_string(), "activation-token".to_string()),
            ("password".to_string(), "long-enough-password".to_string()),
            (
                "password_confirmation".to_string(),
                "long-enough-password".to_string(),
            ),
            ("csrf_token".to_string(), csrf_token.clone()),
        ];
        let duplicate_value = match field {
            "return_to" => "/other".to_string(),
            "token" => "other-activation-token".to_string(),
            "csrf_token" => csrf_token.clone(),
            "password" | "password_confirmation" => "another-long-enough-password".to_string(),
            _ => return Err(format!("unhandled duplicate recovery field: {field}")),
        };
        let mut duplicated = valid_shape.clone();
        duplicated.push((field.to_string(), duplicate_value));

        let err = require_err(
            parse_local_recovery_submission(
                &headers,
                Ok(axum::extract::Form(duplicated)),
                RecoveryTokenPurpose::Activation,
                &store,
            ),
            "duplicate singleton recovery field must be rejected",
        )?;
        assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{field}");

        parse_local_recovery_submission(
            &headers,
            Ok(axum::extract::Form(valid_shape)),
            RecoveryTokenPurpose::Activation,
            &store,
        )
        .map_err(|response| {
            format!(
                "duplicate {field} consumed csrf unexpectedly: {}",
                response.status()
            )
        })?;
    }
    Ok(())
}

#[test]
fn device_user_code_singleton_field_rejects_duplicates() {
    let params = vec![
        ("user_code".to_string(), "AAAA-BBBB".to_string()),
        ("user_code".to_string(), "CCCC-DDDD".to_string()),
    ];

    assert!(reject_duplicate_form_fields(&params, &["user_code"]).is_err());
}

#[test]
fn device_user_code_query_rejects_duplicates() -> TestResult {
    let uri: Uri = "/device?user_code=AAAA-BBBB&user_code=CCCC-DDDD"
        .parse()
        .map_err(|err| format!("valid test URI: {err}"))?;

    let err = require_err(
        parse_device_user_code_query(&uri),
        "duplicate user_code query values must fail closed",
    )?;
    assert_eq!(err, DeviceUserCodeQueryError::DuplicateUserCode);
    Ok(())
}

#[test]
fn device_user_code_query_accepts_single_prefill() -> TestResult {
    let uri: Uri = "/device?ignored=true&user_code=AAAA-BBBB"
        .parse()
        .map_err(|err| format!("valid test URI: {err}"))?;

    let user_code = parse_device_user_code_query(&uri)
        .map_err(|err| format!("device query parse failed: {err:?}"))?;
    assert_eq!(user_code.as_deref(), Some("AAAA-BBBB"));
    Ok(())
}

#[test]
fn request_uri_credential_policy_requires_exact_upstream_callback_shape() {
    assert!(is_upstream_callback_path(
        "/oauth/upstream/enterprise/callback"
    ));
    assert!(!is_upstream_callback_path("/oauth/upstream//callback"));
    assert!(!is_upstream_callback_path(
        "/oauth/upstream/enterprise/callback/extra"
    ));
    assert!(!is_upstream_callback_path(
        "/oauth/upstream/enterprise/not-callback"
    ));

    assert!(uri_credential_policy_for_request(
        &http::Method::GET,
        "/oauth/upstream/enterprise/callback"
    )
    .permits("code"));
    assert!(!uri_credential_policy_for_request(
        &http::Method::POST,
        "/oauth/upstream/enterprise/callback"
    )
    .permits("code"));
    assert!(
        !uri_credential_policy_for_request(&http::Method::GET, "/oauth/upstream//callback")
            .permits("code")
    );
}
