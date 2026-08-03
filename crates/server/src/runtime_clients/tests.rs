use super::*;

use crate::client_registry::{ClientRegistry, ClientSecretCredential, RegisteredClient};

type TestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_ok {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(value) => value,
            Err(err) => fail_test!("{}: {:?}", $context, err),
        }
    };
}

fn runtime_client(client_id: &str, method: &str) -> RegisteredClient {
    RegisteredClient {
        client_id: client_id.to_string(),
        client_secret: None,
        redirect_uris: vec!["https://example.com/callback".to_string()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: method.to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: vec!["read".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        registration_access_token: None,
        client_id_issued_at: None,
    }
}

#[test]
fn runtime_client_projection_coalesces_nullable_dcr_defaults() {
    let query = super::queries::active_runtime_clients_for_issuer_host();

    assert!(query.contains(
        "COALESCE(dcr.post_logout_redirect_uris, ARRAY[]::text[]) AS post_logout_redirect_uris"
    ));
    assert!(query.contains(
        "COALESCE(dcr.backchannel_logout_session_required, false) AS backchannel_logout_session_required"
    ));
}

#[test]
fn runtime_client_rows_and_fingerprint_share_projection_cte() {
    let rows_query = super::queries::active_runtime_clients_for_issuer_host();
    let fingerprint_query = super::queries::active_runtime_client_fingerprint_for_issuer_host();

    for query in [&rows_query, &fingerprint_query] {
        assert!(query.contains("WITH active_runtime_client_projection AS ("));
        assert!(query.contains("jsonb_build_object("));
        assert!(query.contains("'client_secret_credentials'"));
    }
    assert!(rows_query.contains("FROM active_runtime_client_projection"));
    assert!(rows_query.contains("runtime_client_projection_row_json"));
    assert!(fingerprint_query.contains("jsonb_agg(row_json ORDER BY"));
}

#[test]
fn federation_subordinate_entity_list_uses_bounded_runtime_projection_page() {
    let query = super::queries::federation_subordinate_entity_ids_for_issuer_host_keyset_page();

    assert!(query.contains("WITH active_runtime_client_projection AS ("));
    assert!(query.contains("SELECT client_identifier"));
    assert!(query.contains("WHERE client_identifier ~ '^https://"));
    assert!(query.contains("client_identifier > $2"));
    assert!(query.contains("ORDER BY client_identifier ASC"));
    assert!(query.contains("LIMIT $3"));
    assert!(!query.contains("OFFSET"));
}

#[test]
fn snapshot_rejects_duplicate_client_identifiers() {
    let entries = vec![
        RuntimeClientSnapshotEntry {
            client: runtime_client("client-a", "none"),
            client_secret_credentials: Vec::new(),
        },
        RuntimeClientSnapshotEntry {
            client: runtime_client("client-a", "none"),
            client_secret_credentials: Vec::new(),
        },
    ];

    assert!(matches!(
        RuntimeClientSnapshot::try_new(entries),
        Err(RuntimeClientSnapshotError::DuplicateClientIdentifier(client_id))
            if client_id == "client-a"
    ));
}

#[test]
fn snapshot_replace_removes_stale_registry_clients_and_credentials() -> TestResult {
    let registry = ClientRegistry::new_process_local_for_tests();
    registry.register(runtime_client("stale-client", "client_secret_post"));
    registry.register_client_secret_credentials(
        "stale-client",
        vec![ClientSecretCredential::new("stale-hash".to_string(), 1)],
    );

    let credential = ClientSecretCredential::new("active-hash".to_string(), 2);
    let snapshot = must_ok!(
        RuntimeClientSnapshot::try_new_with_fingerprint(
            vec![RuntimeClientSnapshotEntry {
                client: runtime_client("active-client", "client_secret_post"),
                client_secret_credentials: vec![credential.clone()],
            }],
            "runtime-fingerprint".to_string(),
        ),
        "valid snapshot",
    );

    assert_eq!(
        must_ok!(
            snapshot.try_replace_runtime(&registry),
            "snapshot replacement succeeds"
        ),
        1
    );
    assert!(!registry.is_registered_client("stale-client"));
    assert!(registry
        .client_secret_credentials("stale-client")
        .is_empty());
    assert_eq!(
        registry.client_secret_credentials("active-client"),
        vec![credential]
    );
    assert_eq!(
        registry.runtime_snapshot_fingerprint().as_deref(),
        Some("runtime-fingerprint")
    );
    Ok(())
}

#[test]
fn snapshot_register_preserves_existing_runtime_clients() -> TestResult {
    let registry = ClientRegistry::new_process_local_for_tests();
    registry.register(runtime_client("env-client", "none"));

    let credential = ClientSecretCredential::new("db-hash".to_string(), 2);
    let snapshot = must_ok!(
        RuntimeClientSnapshot::try_new(vec![RuntimeClientSnapshotEntry {
            client: runtime_client("db-client", "client_secret_basic"),
            client_secret_credentials: vec![credential.clone()],
        }]),
        "valid snapshot",
    );

    assert_eq!(
        must_ok!(
            snapshot.try_register_runtime(&registry),
            "snapshot registration succeeds"
        ),
        1
    );
    assert!(registry.is_registered_client("env-client"));
    assert!(registry.is_registered_client("db-client"));
    assert_eq!(
        registry.client_secret_credentials("db-client"),
        vec![credential]
    );
    Ok(())
}
