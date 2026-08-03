// -----------------------------------------------------------------------
// S-FED-3: Federation signing with ES256
// -----------------------------------------------------------------------

struct FederationSignerWithoutPublicJwk {
    public_jwk: Option<Value>,
}

fn federation_test_registered_client(client_id: &str) -> crate::client_registry::RegisteredClient {
    crate::client_registry::RegisteredClient {
        client_id: client_id.to_string(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example/callback".to_string()],
        post_logout_redirect_uris: vec!["https://rp.example/logout/callback".to_string()],
        backchannel_logout_uri: Some("https://rp.example/backchannel-logout".to_string()),
        backchannel_logout_session_required: true,
        token_endpoint_auth_method: "private_key_jwt".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: Some("https://rp.example/jwks.json".to_string()),
        token_endpoint_auth_signing_alg: Some("RS256".to_string()),
        allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
        registration_access_token: None,
        client_id_issued_at: Some(1),
    }
}

impl crate::kms::KeyManager for FederationSignerWithoutPublicJwk {
    fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, crate::kms::KeyManagerError> {
        Err(crate::kms::KeyManagerError::OperationFailed)
    }

    fn verify(&self, _msg: &[u8], _sig: &[u8]) -> Result<bool, crate::kms::KeyManagerError> {
        Err(crate::kms::KeyManagerError::OperationFailed)
    }

    fn key_id(&self) -> String {
        "test-key".to_string()
    }

    fn jwt_signing_alg(&self) -> &'static str {
        "disabled"
    }

    fn rotate(&self) -> Result<(), crate::kms::KeyManagerError> {
        Err(crate::kms::KeyManagerError::OperationFailed)
    }

    fn revoke(&self) -> Result<(), crate::kms::KeyManagerError> {
        Err(crate::kms::KeyManagerError::OperationFailed)
    }

    fn sign_federation(&self, _msg: &[u8]) -> Result<Vec<u8>, crate::kms::KeyManagerError> {
        Ok(vec![0; 64])
    }

    fn federation_public_jwk(&self) -> Option<Value> {
        self.public_jwk.clone()
    }
}

#[test]
fn validate_federation_sub_entity_id_rejects_invalid_subjects() {
    for sub in [
        "not-a-url",
        "http://rp.example",
        "https://user@rp.example",
        "https://rp.example?x=1",
        "https://rp.example#frag",
    ] {
        let result = validate_federation_sub_entity_id(sub, "https://op.example");
        assert!(result.is_err(), "invalid sub must be rejected: {sub}");
    }
}

#[test]
fn build_entity_configuration_uses_es256() {
    let km = crate::kms::InMemoryKeyManager::new();
    let jws_result = build_entity_configuration(
        "https://op.example",
        "https://op.example",
        &["https://ta.example".to_string()],
        86400,
        &km,
    );
    assert!(
        jws_result.is_ok(),
        "entity configuration should build for ES256 verification"
    );
    let Ok(jws) = jws_result else {
        return;
    };

    // Parse the JWS header to verify ES256
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "JWS compact must have 3 parts");

    let header_bytes_result = URL_SAFE_NO_PAD.decode(parts[0]);
    assert!(header_bytes_result.is_ok(), "header segment should decode");
    let Ok(header_bytes) = header_bytes_result else {
        return;
    };
    let header_result: Result<Value, _> = serde_json::from_slice(&header_bytes);
    assert!(header_result.is_ok(), "header JSON should parse");
    let Ok(header) = header_result else {
        return;
    };
    assert_eq!(header["alg"], "ES256", "S-FED-3: must use ES256, not HS256");
    assert_eq!(header["typ"], "entity-statement+jwt");
    assert!(header["kid"].is_string(), "kid must be present");

    // Parse the payload to verify JWKS embeds EC public key
    let payload_bytes_result = URL_SAFE_NO_PAD.decode(parts[1]);
    assert!(
        payload_bytes_result.is_ok(),
        "payload segment should decode"
    );
    let Ok(payload_bytes) = payload_bytes_result else {
        return;
    };
    let payload_result: Result<Value, _> = serde_json::from_slice(&payload_bytes);
    assert!(payload_result.is_ok(), "payload JSON should parse");
    let Ok(payload) = payload_result else {
        return;
    };
    assert_eq!(payload["iss"], payload["sub"], "EC-1: iss == sub");
    assert_eq!(
        payload["metadata"]["federation_entity"]["federation_fetch_endpoint"],
        "https://op.example/.well-known/openid-federation/fetch"
    );
    assert_eq!(
        payload["metadata"]["federation_entity"]["federation_resolve_endpoint"],
        "https://op.example/.well-known/openid-federation/resolve"
    );
    assert_eq!(
        payload["metadata"]["federation_entity"]["federation_list_endpoint"],
        "https://op.example/.well-known/openid-federation/list"
    );
    let jwk = &payload["jwks"]["keys"][0];
    assert_eq!(jwk["kty"], "EC", "embedded JWK must be EC");
    assert_eq!(jwk["crv"], "P-256");
    assert!(jwk["x"].is_string(), "x coordinate must be present");
    assert!(jwk["y"].is_string(), "y coordinate must be present");
}

#[test]
fn build_entity_configuration_rejects_invalid_entity_ids() {
    let km = crate::kms::InMemoryKeyManager::new();

    for entity_id in [
        "not-a-url",
        "http://op.example",
        "https://user@op.example",
        "https://op.example?x=1",
        "https://op.example#frag",
    ] {
        assert!(
            build_entity_configuration(entity_id, "https://op.example", &[], 86400, &km).is_err(),
            "invalid entity_id must be rejected: {entity_id}"
        );
    }
}

#[test]
fn build_entity_configuration_rejects_invalid_authority_hints() {
    let km = crate::kms::InMemoryKeyManager::new();

    for authority_hint in [
        "not-a-url",
        "http://ta.example",
        "https://user@ta.example",
        "https://ta.example?x=1",
        "https://ta.example#frag",
        "https://op.example/",
    ] {
        assert!(
            build_entity_configuration(
                "https://op.example",
                "https://op.example",
                &[authority_hint.to_string()],
                86400,
                &km,
            )
            .is_err(),
            "invalid authority hint must be rejected: {authority_hint}"
        );
    }
}

#[test]
fn build_subordinate_statement_uses_es256() {
    let km = crate::kms::InMemoryKeyManager::new();
    let client = federation_test_registered_client("https://rp.example");
    let jws_result = build_subordinate_statement(
        "https://op.example",
        "https://rp.example",
        &client,
        86400,
        &km,
    );
    assert!(
        jws_result.is_ok(),
        "subordinate statement should build for ES256 verification"
    );
    let Ok(jws) = jws_result else {
        return;
    };

    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3);

    let header_bytes_result = URL_SAFE_NO_PAD.decode(parts[0]);
    assert!(header_bytes_result.is_ok(), "header segment should decode");
    let Ok(header_bytes) = header_bytes_result else {
        return;
    };
    let header_result: Result<Value, _> = serde_json::from_slice(&header_bytes);
    assert!(header_result.is_ok(), "header JSON should parse");
    let Ok(header) = header_result else {
        return;
    };
    assert_eq!(header["alg"], "ES256", "S-FED-3: must use ES256");

    let payload_bytes_result = URL_SAFE_NO_PAD.decode(parts[1]);
    assert!(
        payload_bytes_result.is_ok(),
        "payload segment should decode"
    );
    let Ok(payload_bytes) = payload_bytes_result else {
        return;
    };
    let payload_result: Result<Value, _> = serde_json::from_slice(&payload_bytes);
    assert!(payload_result.is_ok(), "payload JSON should parse");
    let Ok(payload) = payload_result else {
        return;
    };
    assert_eq!(payload["iss"], "https://op.example", "SS-1: iss = OP");
    assert_eq!(payload["sub"], "https://rp.example", "SS-2: sub = RP");
    assert_ne!(payload["iss"], payload["sub"], "SS-3: iss != sub");
    assert_eq!(
        payload["metadata_policy"],
        json!({}),
        "local subordinate statements must carry an explicit empty metadata_policy"
    );
    assert_eq!(
        payload["metadata"]["openid_relying_party"]["client_id"],
        "https://rp.example"
    );
    assert_eq!(
        payload["metadata"]["openid_relying_party"]["redirect_uris"],
        json!(["https://rp.example/callback"])
    );
    assert_eq!(
        payload["metadata"]["openid_relying_party"]["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(
        payload["metadata"]["openid_relying_party"]["response_types"],
        json!(["code"])
    );
    assert_eq!(
        payload["metadata"]["openid_relying_party"]["jwks_uri"],
        "https://rp.example/jwks.json"
    );
}

#[test]
fn build_subordinate_statement_rejects_invalid_or_self_subjects() {
    let km = crate::kms::InMemoryKeyManager::new();

    for (issuer, subject) in [
        ("https://op.example", "not-a-url"),
        ("https://op.example", "http://rp.example"),
        ("https://op.example", "https://rp.example?x=1"),
        ("https://op.example", "https://op.example/"),
    ] {
        let client = federation_test_registered_client(subject);
        assert!(
            build_subordinate_statement(issuer, subject, &client, 86400, &km).is_err(),
            "invalid subordinate statement subject must be rejected: {subject}"
        );
    }
}

#[test]
fn build_resolve_response_uses_resolve_response_typ_and_trust_chain_claim() {
    let km = crate::kms::InMemoryKeyManager::new();
    let jws_result = build_resolve_response(
        "https://op.example",
        "https://rp.example",
        100,
        200,
        json!({
            "openid_provider": {
                "issuer": "https://rp.example"
            }
        }),
        vec!["leaf.entity.statement.jwt".to_string()],
        &km,
    );
    assert!(
        jws_result.is_ok(),
        "resolve response should build for a non-empty trust chain"
    );
    let Ok(jws) = jws_result else {
        return;
    };

    let parts = jws.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "JWS compact must have 3 parts");

    let header_bytes_result = URL_SAFE_NO_PAD.decode(parts[0]);
    assert!(header_bytes_result.is_ok(), "header segment should decode");
    let Ok(header_bytes) = header_bytes_result else {
        return;
    };
    let header_result: Result<Value, _> = serde_json::from_slice(&header_bytes);
    assert!(header_result.is_ok(), "header JSON should parse");
    let Ok(header) = header_result else {
        return;
    };
    assert_eq!(header["typ"], "resolve-response+jwt");
    assert_eq!(header["alg"], "ES256");

    let payload_bytes_result = URL_SAFE_NO_PAD.decode(parts[1]);
    assert!(
        payload_bytes_result.is_ok(),
        "payload segment should decode"
    );
    let Ok(payload_bytes) = payload_bytes_result else {
        return;
    };
    let payload_result: Result<Value, _> = serde_json::from_slice(&payload_bytes);
    assert!(payload_result.is_ok(), "payload JSON should parse");
    let Ok(payload) = payload_result else {
        return;
    };
    assert_eq!(payload["iss"], "https://op.example");
    assert_eq!(payload["sub"], "https://rp.example");
    assert_eq!(payload["iat"], 100);
    assert_eq!(payload["exp"], 200);
    assert_eq!(payload["trust_chain"][0], "leaf.entity.statement.jwt");
    assert_eq!(
        payload["metadata"]["openid_provider"]["issuer"],
        "https://rp.example"
    );
}

#[test]
fn federation_statements_require_public_jwk_kid() {
    let missing_public_jwk = FederationSignerWithoutPublicJwk { public_jwk: None };
    let client = federation_test_registered_client("https://rp.example");
    assert!(
        build_subordinate_statement(
            "https://op.example",
            "https://rp.example",
            &client,
            86400,
            &missing_public_jwk,
        )
        .is_err(),
        "subordinate statements must not be signed without public verification material"
    );

    let missing_kid = FederationSignerWithoutPublicJwk {
        public_jwk: Some(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "AA",
            "y": "AA",
            "alg": "ES256",
        })),
    };
    assert!(
        build_entity_configuration(
            "https://op.example",
            "https://op.example",
            &[],
            86400,
            &missing_kid,
        )
        .is_err(),
        "entity configurations must not be signed with a key that has no kid"
    );
}

#[test]
fn entity_configuration_signature_verifies() {
    let km = crate::kms::InMemoryKeyManager::new();
    let jws_result =
        build_entity_configuration("https://op.example", "https://op.example", &[], 86400, &km);
    assert!(
        jws_result.is_ok(),
        "entity configuration should build for signature verification"
    );
    let Ok(jws) = jws_result else {
        return;
    };

    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3);

    // Extract the embedded JWKS public key from the payload
    let payload_bytes_result = URL_SAFE_NO_PAD.decode(parts[1]);
    assert!(
        payload_bytes_result.is_ok(),
        "payload segment should decode"
    );
    let Ok(payload_bytes) = payload_bytes_result else {
        return;
    };
    let payload_result: Result<Value, _> = serde_json::from_slice(&payload_bytes);
    assert!(payload_result.is_ok(), "payload JSON should parse");
    let Ok(payload) = payload_result else {
        return;
    };
    let jwk = &payload["jwks"]["keys"][0];
    let x_value = jwk["x"].as_str();
    let y_value = jwk["y"].as_str();
    assert!(x_value.is_some(), "x coordinate should be present");
    assert!(y_value.is_some(), "y coordinate should be present");
    let Some(x_value) = x_value else {
        return;
    };
    let Some(y_value) = y_value else {
        return;
    };
    let x_result = URL_SAFE_NO_PAD.decode(x_value);
    let y_result = URL_SAFE_NO_PAD.decode(y_value);
    assert!(x_result.is_ok(), "x coordinate should decode");
    assert!(y_result.is_ok(), "y coordinate should decode");
    let Ok(x) = x_result else {
        return;
    };
    let Ok(y) = y_result else {
        return;
    };
    let mut pub_key = Vec::with_capacity(65);
    pub_key.push(0x04);
    pub_key.extend_from_slice(&x);
    pub_key.extend_from_slice(&y);

    // Verify the signature against the signing input
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_result = URL_SAFE_NO_PAD.decode(parts[2]);
    assert!(signature_result.is_ok(), "signature segment should decode");
    let Ok(sig) = signature_result else {
        return;
    };
    let verify_result = aegaeon_crypto::signature::verify_ecdsa_p256_fixed(
        &pub_key,
        signing_input.as_bytes(),
        &sig,
    );
    assert!(
        verify_result.is_ok(),
        "entity config ES256 signature must verify against embedded JWKS"
    );
}
