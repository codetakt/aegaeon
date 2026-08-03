use super::*;

#[test]
fn test_store_and_consume() -> TestResult {
    let store = ParStore::new_process_local_for_tests();
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

    let response = test_context(
        process_par_request(&store, request.clone()),
        "store request",
    )?;
    assert!(response.request_uri.starts_with("urn:aegaeon:par:"));
    assert_eq!(response.expires_in, 90);

    let retrieved = consume_request(&store, &response.request_uri)?
        .ok_or_else(|| "stored PAR request should be retrievable exactly once".to_string())?;
    assert_eq!(retrieved.client_id, request.client_id);
    assert_eq!(retrieved.state, request.state);

    assert!(consume_request(&store, &response.request_uri)?.is_none());
    Ok(())
}

#[test]
fn test_resolve_request_reserves_front_channel_use() -> TestResult {
    let store = ParStore::new_process_local_for_tests();
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

    let response = test_context(process_par_request(&store, request), "store request")?;
    assert!(resolve_request(&store, &response.request_uri)?.is_some());
    assert!(resolve_request(&store, &response.request_uri)?.is_none());
    assert!(consume_request(&store, &response.request_uri)?.is_some());
    assert!(resolve_request(&store, &response.request_uri)?.is_none());
    Ok(())
}

#[test]
fn reserved_request_resumes_only_with_matching_continuation() -> TestResult {
    let store = ParStore::new_process_local_for_tests();
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

    let response = test_context(process_par_request(&store, request), "store request")?;
    let reserved = test_context(
        store.reserve_request_for_client(&response.request_uri, "test_client"),
        "first authorize use reserves request",
    )?;

    assert!(
        store
            .reserve_request_for_client(&response.request_uri, "test_client")
            .is_err(),
        "request_uri must not be independently re-reserved"
    );
    assert!(
        store
            .resume_request_for_client(&response.request_uri, "test_client", "wrong")
            .is_err(),
        "wrong continuation must fail closed"
    );
    let resumed = test_context(
        store.resume_request_for_client(
            &response.request_uri,
            "test_client",
            &reserved.continuation,
        ),
        "matching continuation resumes reserved request",
    )?;
    assert_eq!(resumed.client_id, reserved.request.client_id);
    assert!(consume_request(&store, &response.request_uri)?.is_some());
    assert!(
        store
            .resume_request_for_client(&response.request_uri, "test_client", &reserved.continuation)
            .is_err(),
        "consumed request_uri must not resume"
    );
    Ok(())
}

#[test]
fn test_expiry() -> TestResult {
    let store = ParStore::new_process_local_for_tests();
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
        state: None,
        code_challenge: None,
        code_challenge_method: None,
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

    // Create expired request manually
    let request_uri = ParStore::generate_request_uri();
    let expired = StoredParRequest {
        client_id: request.client_id.clone(),
        request,
        expires_at: SystemTime::now() - Duration::from_secs(1),
        authorize_continuation: None,
    };

    store
        .insert_stored_request_for_test(&request_uri, expired)
        .map_err(|err| format!("expired request fixture insert failed: {err}"))?;

    // Should not retrieve expired request
    assert!(consume_request(&store, &request_uri)?.is_none());
    Ok(())
}
