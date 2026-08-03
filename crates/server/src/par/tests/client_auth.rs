use super::*;

#[test]
fn hash_backed_client_secret_authentication_enforces_expiry() -> TestResult {
    let store = ParStore::new_process_local_for_tests();
    store.register_client(Client {
        client_id: "db_client".to_string(),
        client_secret: None,
        token_endpoint_auth_method: "client_secret_post".to_string(),
        redirect_uris: vec!["https://example.com/callback".to_string()],
        allowed_scopes: vec!["read".to_string()],
    });

    let active_hash = crate::local_credentials::hash_password("db-secret")
        .map_err(|err| format!("hash active secret: {err}"))?;
    let expired_hash = crate::local_credentials::hash_password("expired-secret")
        .map_err(|err| format!("hash expired secret: {err}"))?;
    let now_epoch_secs: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("test clock before epoch: {err}"))?
        .as_secs()
        .try_into()
        .map_err(|err| format!("epoch seconds fit i64: {err}"))?;
    store.register_client_secret_credentials(
        "db_client",
        vec![
            ClientSecretCredential::new(active_hash, now_epoch_secs + 60),
            ClientSecretCredential::new(expired_hash, now_epoch_secs - 1),
        ],
    );

    let request = |client_secret: Option<&str>| ParRequest {
        client_id: "db_client".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        response_type: "code".to_string(),
        iss: None,
        resource: None,
        state: None,
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        scope: Some("read".to_string()),
        nonce: None,
        acr_values: None,
        max_age: None,
        authorization_details: None,
        client_secret: client_secret.map(str::to_string),

        client_authenticated: false,

        request_object: None,
        request_object_claims: None,
    };

    assert!(process_par_request(&store, request(Some("db-secret"))).is_ok());

    let wrong_secret = test_err(
        process_par_request(&store, request(Some("wrong"))),
        "wrong secret must fail closed",
    )?;
    assert_eq!(wrong_secret.error, "invalid_client");

    let expired_secret = test_err(
        process_par_request(&store, request(Some("expired-secret"))),
        "expired secret must fail closed",
    )?;
    assert_eq!(expired_secret.error, "invalid_client");

    let missing_secret = test_err(
        process_par_request(&store, request(None)),
        "missing secret must fail closed",
    )?;
    assert_eq!(missing_secret.error, "invalid_client");
    Ok(())
}

#[test]
fn replace_clients_removes_stale_clients_and_credentials() -> TestResult {
    let store = ParStore::new_process_local_for_tests();
    store.register_client(Client {
        client_id: "stale_client".to_string(),
        client_secret: Some("stale-secret".to_string()),
        token_endpoint_auth_method: "client_secret_post".to_string(),
        redirect_uris: vec!["https://example.com/callback".to_string()],
        allowed_scopes: vec!["read".to_string()],
    });
    store.register_client_secret_credentials(
        "stale_client",
        vec![ClientSecretCredential::new("stale-hash".to_string(), 10)],
    );

    let active_hash = crate::local_credentials::hash_password("active-secret")
        .map_err(|err| format!("hash active secret: {err}"))?;
    let now_epoch_secs: i64 = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("test clock before epoch: {err}"))?
        .as_secs()
        .try_into()
        .map_err(|err| format!("epoch seconds fit i64: {err}"))?;
    let active = Client {
        client_id: "active_client".to_string(),
        client_secret: None,
        token_endpoint_auth_method: "client_secret_post".to_string(),
        redirect_uris: vec!["https://example.com/callback".to_string()],
        allowed_scopes: vec!["read".to_string()],
    };

    store.replace_clients(
        HashMap::from([(active.client_id.clone(), active)]),
        HashMap::from([
            (
                "active_client".to_string(),
                vec![ClientSecretCredential::new(
                    active_hash,
                    now_epoch_secs.saturating_add(60),
                )],
            ),
            (
                "orphan_client".to_string(),
                vec![ClientSecretCredential::new("orphan-hash".to_string(), 20)],
            ),
        ]),
    );

    assert!(!test_context(
        try_read_lock(&store.clients, "clients read"),
        "PAR test clients lock"
    )?
    .contains_key("stale_client"));
    assert!(!try_read_lock(
        &store.client_secret_credentials,
        "client secret credentials read"
    )
    .map_err(|err| format!("PAR test client-secret credentials lock: {err}"))?
    .contains_key("stale_client"));
    assert!(!try_read_lock(
        &store.client_secret_credentials,
        "client secret credentials read"
    )
    .map_err(|err| format!("PAR test client-secret credentials lock: {err}"))?
    .contains_key("orphan_client"));

    let request = |client_id: &str, client_secret: Option<&str>| ParRequest {
        client_id: client_id.to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        response_type: "code".to_string(),
        iss: None,
        resource: None,
        state: None,
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        scope: Some("read".to_string()),
        nonce: None,
        acr_values: None,
        max_age: None,
        authorization_details: None,
        client_secret: client_secret.map(str::to_string),
        client_authenticated: false,
        request_object: None,
        request_object_claims: None,
    };

    assert!(process_par_request(&store, request("active_client", Some("active-secret"))).is_ok());
    assert_eq!(
        test_err(
            process_par_request(&store, request("stale_client", Some("stale-secret"))),
            "stale client must be removed"
        )?
        .error,
        "invalid_client"
    );
    Ok(())
}

#[test]
fn non_secret_confidential_client_requires_endpoint_authentication() -> TestResult {
    let store = ParStore::new_process_local_for_tests();
    store.register_client(Client {
        client_id: "pkjwt_client".to_string(),
        client_secret: None,
        token_endpoint_auth_method: "private_key_jwt".to_string(),
        redirect_uris: vec!["https://example.com/callback".to_string()],
        allowed_scopes: vec!["read".to_string()],
    });

    let request = |client_authenticated| ParRequest {
        client_id: "pkjwt_client".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        response_type: "code".to_string(),
        iss: None,
        resource: None,
        state: None,
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        scope: Some("read".to_string()),
        nonce: None,
        acr_values: None,
        max_age: None,
        authorization_details: None,
        client_secret: None,
        client_authenticated,
        request_object: None,
        request_object_claims: None,
    };

    let unauthenticated = test_err(
        process_par_request(&store, request(false)),
        "unauthenticated confidential client must fail closed",
    )?;
    assert_eq!(unauthenticated.error, "invalid_client");
    assert!(process_par_request(&store, request(true)).is_ok());
    Ok(())
}

#[test]
fn non_secret_confidential_client_rejects_stray_client_secret() -> TestResult {
    let store = ParStore::new_process_local_for_tests();
    store.register_client(Client {
        client_id: "pkjwt_client".to_string(),
        client_secret: None,
        token_endpoint_auth_method: "private_key_jwt".to_string(),
        redirect_uris: vec!["https://example.com/callback".to_string()],
        allowed_scopes: vec!["read".to_string()],
    });

    let request = ParRequest {
        client_id: "pkjwt_client".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        response_type: "code".to_string(),
        iss: None,
        resource: None,
        state: None,
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        scope: Some("read".to_string()),
        nonce: None,
        acr_values: None,
        max_age: None,
        authorization_details: None,
        client_secret: Some("stray-secret".to_string()),
        client_authenticated: true,
        request_object: None,
        request_object_claims: None,
    };

    let err = test_err(
        process_par_request(&store, request),
        "stray client secret must fail closed",
    )?;

    assert_eq!(err.error, "invalid_client");
    Ok(())
}
