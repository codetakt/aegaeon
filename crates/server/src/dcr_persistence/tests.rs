use super::*;
use std::collections::BTreeSet;

#[test]
fn registration_access_token_hash_is_lowercase_sha256_hex() {
    let hash = registration_access_token_hash("registration-token");

    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert_eq!(hash, hash.to_ascii_lowercase());
}

#[test]
fn dcr_bearer_token_hash_is_lowercase_sha256_hex() {
    let hash = dcr_bearer_token_hash("registration-gate-token");

    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert_eq!(hash, hash.to_ascii_lowercase());
}

#[test]
fn client_auth_method_secret_detection_is_strict() {
    assert!(client_auth_method_uses_secret("client_secret_basic"));
    assert!(client_auth_method_uses_secret(" client_secret_post "));
    assert!(!client_auth_method_uses_secret("none"));
    assert!(!client_auth_method_uses_secret("private_key_jwt"));
}

#[test]
fn dynamic_registration_access_token_is_required_for_persistence() {
    assert!(require_dynamic_registration_access_token("registration-token").is_ok());
    assert!(matches!(
        require_dynamic_registration_access_token("   "),
        Err(DcrDatabaseError::CorruptRegistration(message))
            if message == "registration_access_token is missing"
    ));
}

#[test]
fn dynamic_registration_client_id_issued_at_is_required_for_persistence() {
    let client = RegisteredClient {
        client_id: "client-id".to_string(),
        client_secret: None,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: "none".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: Vec::new(),
        allowed_grant_types: Vec::new(),
        registration_access_token: None,
        client_id_issued_at: None,
    };

    assert!(matches!(
        require_dynamic_registration_client_id_issued_at(&client),
        Err(DcrDatabaseError::CorruptRegistration(message))
            if message == "client_id_issued_at is missing"
    ));
}

#[test]
fn dynamic_registration_schema_deficit_is_empty_for_complete_inventory() {
    let inventory = DynamicRegistrationSchemaInventory {
        columns: REQUIRED_DCR_COLUMNS
            .iter()
            .map(ToString::to_string)
            .collect(),
        indexes: REQUIRED_DCR_INDEXES
            .iter()
            .map(ToString::to_string)
            .collect(),
        constraints: REQUIRED_DCR_CONSTRAINTS
            .iter()
            .map(ToString::to_string)
            .collect(),
    };

    assert!(DynamicRegistrationSchemaDeficit::from_inventory(&inventory).is_empty());
}

#[test]
fn dynamic_registration_schema_deficit_reports_missing_contract_items() {
    let inventory = DynamicRegistrationSchemaInventory {
        columns: REQUIRED_DCR_COLUMNS
            .iter()
            .copied()
            .filter(|column| *column != "jwks")
            .map(ToString::to_string)
            .collect(),
        indexes: BTreeSet::new(),
        constraints: REQUIRED_DCR_CONSTRAINTS
            .iter()
            .copied()
            .filter(|constraint| *constraint != "dynamic_client_registrations_token_hash_shape")
            .map(ToString::to_string)
            .collect(),
    };
    let deficit = DynamicRegistrationSchemaDeficit::from_inventory(&inventory);

    assert_eq!(deficit.missing_columns, vec!["jwks"]);
    assert_eq!(deficit.missing_indexes, REQUIRED_DCR_INDEXES.to_vec());
    assert_eq!(
        deficit.missing_constraints,
        vec!["dynamic_client_registrations_token_hash_shape"]
    );
    assert_eq!(
        deficit.describe(false),
        concat!(
            "aegaeon.dynamic_client_registrations is missing required schema items ",
            "(missing columns: jwks; ",
            "missing indexes: dynamic_client_registrations_env_identifier_unique, ",
            "dynamic_client_registrations_env_token_hash_unique; ",
            "missing constraints: dynamic_client_registrations_token_hash_shape); ",
            "apply the aegaeon schema baseline (atlas migrate apply --env local)"
        )
    );
}

#[test]
fn dynamic_registration_schema_deficit_reports_missing_table_clearly() {
    let deficit = DynamicRegistrationSchemaDeficit::from_inventory(
        &DynamicRegistrationSchemaInventory::default(),
    );

    assert_eq!(
        deficit.describe(true),
        concat!(
            "missing or inaccessible aegaeon.dynamic_client_registrations; ",
            "apply the aegaeon schema baseline (atlas migrate apply --env local)"
        )
    );
}
