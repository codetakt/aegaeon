use super::*;
use crate::client_registry::RegisteredClientJwks;
use crate::dcr::{validate_registration, ClientRegistration};
use crate::test_utils::jwk_usage::material;
use jsonwebtoken::Algorithm;
use serde_json::json;
use std::collections::HashSet;

#[test]
fn public_client_jwks_rejects_each_secret_presence_before_parser_diagnostics() {
    let (rsa, _) = material(Algorithm::RS256);
    let (ec, _) = material(Algorithm::ES256);
    let mut encryption = rsa.clone();
    encryption["use"] = json!("enc");
    for base in [
        rsa.clone(),
        ec,
        encryption,
        json!({"kty":"oct"}),
        json!({"kty":"unknown-sentinel"}),
    ] {
        for field in PRIVATE_MEMBERS {
            for private in [
                Value::Null,
                json!("private-sentinel"),
                json!(7),
                json!({"nested":"private-sentinel"}),
            ] {
                let mut key = base.clone();
                key["kid"] = json!("kid-sentinel");
                key["extra"] = json!("extension-sentinel");
                key[*field] = private;
                // A structurally invalid earlier member must not reflect its kty.
                let set = json!({"keys":[{"kty":"parser-sentinel"},rsa,key]});
                let expected = format!("public jwks key index 2 contains forbidden member {field}");
                assert_eq!(
                    RegisteredClientJwks::from_value(set.clone(), false).unwrap_err(),
                    expected
                );
                let registration = ClientRegistration {
                    jwks: Some(set),
                    ..Default::default()
                };
                assert_eq!(
                    validate_registration(&registration, false, &HashSet::<String>::new())
                        .unwrap_err(),
                    expected
                );
            }
        }
    }
}

#[test]
fn legacy_client_jwks_projection_preserves_public_data_and_structural_domain() {
    let (mut key, _) = material(Algorithm::RS256);
    key["x5c"] = json!(["unchanged-certificate"]);
    key["extension"] = json!({"d":"nested-extension"});
    let mut other = key.clone();
    other["kid"] = json!("unusable");
    other["n"] = json!("AA");
    let public = json!({"keys":[other,key],"extension":{"k":"set-extension"}});
    let mut stored = public.clone();
    for key in stored["keys"].as_array_mut().unwrap() {
        for field in PRIVATE_MEMBERS {
            key[*field] = json!("private-sentinel");
        }
    }
    let loaded = RegisteredClientJwks::from_stored_value(stored.clone()).unwrap();
    assert_eq!(loaded.as_value(), &public);
    assert!(loaded.select(Some("unusable")).is_none());
    assert!(loaded.select(Some("usage-key")).is_some());
    assert!(!format!("{loaded:?}").contains("private-sentinel"));
    assert!(RegisteredClientJwks::from_value(stored.clone(), false).is_err());
    let generic = aegaeon_jose::jwk::JwkSet::from_value(stored).unwrap();
    assert!(generic.keys()[0].extra.contains_key("d"));
    for malformed in [
        Value::Null,
        json!({"keys":null}),
        json!({"keys":[null]}),
        json!({"keys":[{"kty":"RSA","d":null}]}),
        json!({"keys":[{"kty":"oct","k":null}]}),
    ] {
        assert!(RegisteredClientJwks::from_stored_value(malformed).is_err());
    }
}
