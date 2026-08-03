#[test]
fn runtime_client_mutation_sync_uses_database_snapshot() -> TestResult {
    let clients = crate::client_registry::ClientRegistry::new_process_local_for_tests();
    let runtime_authority =
        crate::web::RuntimeAuthorityState::new_process_local_for_tests(" auth.example.com ");
    let runtime_restart = crate::runtime_restart::RuntimeRestartState::new();
    let sync = RuntimeClientMutationSync {
        runtime_authority: &runtime_authority,
        runtime_restart: &runtime_restart,
        clients: &clients,
    };

    assert_eq!(
        sync.database_issuer_host_for_snapshot_sync("req-1")
            .map_err(|_| io::Error::other("issuer host"))?,
        "auth.example.com"
    );
    Ok(())
}

#[test]
fn runtime_client_mutation_sync_rejects_missing_database_issuer_host() -> TestResult {
    let clients = crate::client_registry::ClientRegistry::new_process_local_for_tests();
    let runtime_authority =
        crate::web::RuntimeAuthorityState::new_process_local_for_tests("   ");
    let runtime_restart = crate::runtime_restart::RuntimeRestartState::new();
    let sync = RuntimeClientMutationSync {
        runtime_authority: &runtime_authority,
        runtime_restart: &runtime_restart,
        clients: &clients,
    };

    let response = must_err!(
        sync.database_issuer_host_for_snapshot_sync("req-1"),
        "empty issuer host must fail closed"
    );

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.headers().get("x-request-id"),
        Some(&HeaderValue::from_static("req-1"))
    );
    Ok(())
}
