use super::*;

#[test]
fn test_request_uri_generation() {
    let uri1 = ParStore::generate_request_uri();
    let uri2 = ParStore::generate_request_uri();

    assert!(uri1.starts_with("urn:aegaeon:par:"));
    assert!(uri2.starts_with("urn:aegaeon:par:"));
    assert_ne!(uri1, uri2); // Should be unique
}

#[test]
fn par_expires_range_is_bounded() {
    assert!(!ParStore::valid_expires_in(0));
    assert!(ParStore::valid_expires_in(1));
    assert!(ParStore::valid_expires_in(90));
    assert!(ParStore::valid_expires_in(ParStore::MAX_PAR_EXPIRES_IN));
    assert!(!ParStore::valid_expires_in(
        ParStore::MAX_PAR_EXPIRES_IN + 1
    ));
}

#[test]
fn explicit_par_expires_in_rejects_unbounded_values() -> TestResult {
    let namespace = crate::config::RuntimeStateNamespace::for_tests("par-test");
    let err = test_err(
        ParStore::try_new_from_shared_store_env_with_expires_in(
            ParStore::MAX_PAR_EXPIRES_IN + 1,
            &namespace,
        ),
        "unbounded PAR TTL must fail closed",
    )?;

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "par_expires_in_seconds"
    ));
    Ok(())
}

#[test]
fn store_request_rejects_unrepresentable_expiry() -> TestResult {
    let store = ParStore::new_process_local_for_tests();
    store.set_expires_in(u64::MAX);
    store.register_client(Client {
        client_id: "test_client".to_string(),
        client_secret: Some("secret".to_string()),
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        redirect_uris: vec!["https://example.com/callback".to_string()],
        allowed_scopes: vec![],
    });

    let request = ParRequest {
        client_id: "test_client".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        response_type: "code".to_string(),
        iss: None,
        resource: None,
        state: Some("state123".to_string()),
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        scope: None,
        nonce: None,
        acr_values: None,
        max_age: None,
        authorization_details: None,
        client_secret: Some("secret".to_string()),
        client_authenticated: false,
        request_object: None,
        request_object_claims: None,
    };

    let error = test_err(
        process_par_request(&store, request),
        "overflow must fail closed",
    )?;
    assert_eq!(error.error, "server_error");
    Ok(())
}

#[test]
fn try_authorize_continuation_reports_store_unavailable() -> TestResult {
    let store = ParStore::with_request_store(60, Arc::new(UnavailableParRequestStore));

    let error = test_err(
        store.try_authorize_continuation("urn:aegaeon:par:missing"),
        "store outage must be reported",
    )?;
    assert_eq!(error.error, "server_error");
    Ok(())
}
