use super::*;
use crate::federation::admission::{admit_entity_configuration, admit_subordinate_statement};

const NOW: i64 = 1_800_000_000;
const ENTITY: &str = "https://rp.example";
const AUTHORITY: &str = "https://ta.example";

pub(super) fn sign_payload(payload: &str) -> String {
    let key = sample_signing_key();
    let jwk = must_some(FederationKeyManager::federation_public_jwk(key));
    let header = json!({"alg": "ES256", "typ": "entity-statement+jwt", "kid": jwk["kid"]});
    let input = format!(
        "{}.{}",
        encode_json_value(&header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = must_ok(FederationKeyManager::sign_federation(key, input.as_bytes()));
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

#[test]
fn individual_configuration_binds_signed_identity_profile_and_time() {
    let _guard = raw_json_env_guard();
    let valid = sample_entity_config(ENTITY, NOW);
    let raw = sign_entity_statement_for_test(sample_signing_key(), &valid);
    assert_eq!(
        must_ok(admit_entity_configuration(&raw, ENTITY, NOW)).sub,
        ENTITY
    );
    assert!(admit_entity_configuration(&raw, "https://other.example", NOW).is_err());
    assert!(admit_entity_configuration("invalid", ENTITY, NOW).is_err());
    let mut parts: Vec<_> = raw.split('.').map(str::to_string).collect();
    let mut signature = must_ok(URL_SAFE_NO_PAD.decode(&parts[2]));
    signature[0] ^= 1;
    parts[2] = URL_SAFE_NO_PAD.encode(signature);
    let invalid_signature = parts.join(".");
    assert!(admit_entity_configuration(&invalid_signature, ENTITY, NOW).is_err());
    for (iat, exp) in [(NOW - 200, NOW - 61), (NOW + 61, NOW + 100), (NOW, NOW)] {
        let mut statement = valid.clone();
        statement.iat = iat;
        statement.exp = exp;
        let raw = sign_entity_statement_for_test(sample_signing_key(), &statement);
        assert!(admit_entity_configuration(&raw, ENTITY, NOW).is_err());
        // The generic verifier keeps its documented signature/profile-only contract.
        if exp > iat {
            assert!(verify_entity_configuration(&raw).is_ok());
        }
    }
    let mut value = must_ok(serde_json::to_value(valid));
    must_some(value.as_object_mut()).remove("iat");
    let malformed = sign_payload(&must_ok(serde_json::to_string(&value)));
    assert!(admit_entity_configuration(&malformed, ENTITY, NOW).is_err());
}

#[test]
fn individual_configuration_compares_decoded_strings_without_transport_aliases() {
    let _guard = raw_json_env_guard();
    for (signed, requested) in [
        ("https://RP.example", "https://rp.example"),
        ("https://rp.example:443", "https://rp.example"),
        ("https://rp.example/", "https://rp.example"),
        ("https://rp.example/a/../b", "https://rp.example/b"),
    ] {
        let statement = sample_entity_config(signed, NOW);
        let raw = sign_entity_statement_for_test(sample_signing_key(), &statement);
        assert!(
            admit_entity_configuration(&raw, signed, NOW).is_ok(),
            "{signed}"
        );
        assert!(
            admit_entity_configuration(&raw, requested, NOW).is_err(),
            "{signed}"
        );
        assert_eq!(
            must_ok(entity_configuration_url(signed)),
            must_ok(entity_configuration_url(requested))
        );
    }
    let value = must_ok(serde_json::to_string(&sample_entity_config(ENTITY, NOW)));
    let raw = sign_payload(&value.replace("https://rp.example", "https:\\u002f\\u002frp.example"));
    assert_eq!(
        must_ok(admit_entity_configuration(&raw, ENTITY, NOW)).sub,
        ENTITY
    );
}

#[test]
fn individual_subordinate_binds_issuer_subject_kind_time_and_independent_key() {
    let _guard = raw_json_env_guard();
    let valid = sample_subordinate_statement(AUTHORITY, ENTITY, NOW);
    let raw = sign_entity_statement_for_test(sample_signing_key(), &valid);
    assert_eq!(
        must_ok(admit_subordinate_statement(
            &raw,
            AUTHORITY,
            ENTITY,
            &sample_jwks(),
            NOW
        ))
        .sub,
        ENTITY
    );
    assert!(admit_subordinate_statement(
        &raw,
        "https://other.example",
        ENTITY,
        &sample_jwks(),
        NOW
    )
    .is_err());
    assert!(admit_subordinate_statement(
        &raw,
        AUTHORITY,
        "https://other.example",
        &sample_jwks(),
        NOW
    )
    .is_err());
    let other = must_ok(JwkSet::from_value(federation_jwks_value(
        &InMemoryKeyManager::new(),
    )));
    assert!(admit_subordinate_statement(&raw, AUTHORITY, ENTITY, &other, NOW).is_err());
    let self_signed =
        sign_entity_statement_for_test(sample_signing_key(), &sample_entity_config(AUTHORITY, NOW));
    assert!(
        admit_subordinate_statement(&self_signed, AUTHORITY, AUTHORITY, &sample_jwks(), NOW)
            .is_err()
    );
    for (iat, exp) in [(NOW - 200, NOW - 61), (NOW + 61, NOW + 100), (NOW, NOW)] {
        let mut statement = valid.clone();
        statement.iat = iat;
        statement.exp = exp;
        let raw = sign_entity_statement_for_test(sample_signing_key(), &statement);
        assert!(admit_subordinate_statement(&raw, AUTHORITY, ENTITY, &sample_jwks(), NOW).is_err());
    }
    let mut value = must_ok(serde_json::to_value(valid));
    value["authority_hints"] = json!([AUTHORITY]);
    let malformed = sign_payload(&must_ok(serde_json::to_string(&value)));
    assert!(
        admit_subordinate_statement(&malformed, AUTHORITY, ENTITY, &sample_jwks(), NOW).is_err()
    );
    assert!(
        admit_subordinate_statement("invalid", AUTHORITY, ENTITY, &sample_jwks(), NOW).is_err()
    );
}

#[test]
fn http_subordinate_checks_authority_before_attempting_transport() {
    let _guard = raw_json_env_guard();
    let now = current_epoch_secs();
    let fetcher = must_ok(HttpFederationFetcher::try_new());
    for mode in 0..4 {
        let mut authority = sample_entity_config(AUTHORITY, now);
        match mode {
            0 => authority.sub = ENTITY.into(),
            1 => authority.iat = now + 61,
            2 => {
                authority.iat = now - 200;
                authority.exp = now - 61;
            }
            _ => authority.jwks = None,
        }
        // There is no advertised endpoint. Admission must reject before even URL construction.
        let error = must_err(block_on_test_future(fetcher.fetch_subordinate_statement(
            AUTHORITY,
            &authority,
            ENTITY,
            &sample_jwks(),
        )));
        assert!(!error.to_string().contains("missing advertised"));
        assert!(!matches!(error, FederationError::Fetch(_)));
        assert!(
            block_on_test_future(fetcher.fetch_subordinate_statement_with_jws(
                AUTHORITY,
                &authority,
                ENTITY,
                &sample_jwks(),
            ))
            .is_err()
        );
    }
}
