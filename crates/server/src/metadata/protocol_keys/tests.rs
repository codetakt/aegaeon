use super::*;
use serde_json::json;

#[test]
fn supplied_public_protocol_profiles_keep_partial_and_opaque_values() {
    for role in [
        "openid_provider",
        "openid_relying_party",
        "oauth_authorization_server",
        "oauth_client",
        "oauth_resource",
    ] {
        for value in [
            json!({}),
            json!({"jwks":{"keys":[]}}),
            json!({
                "jwks":{"keys":[null,7,{}, {"kty":"future","extension":{"d":null}}],"extension":null},
                "jwks_uri":"HTTPS://Keys.example:8443/path?q=1",
                "signed_jwks_uri":"https://keys.example/signed"
            }),
        ] {
            let original = value.clone();
            assert!(validate_supplied(role, value.as_object().unwrap()).is_ok());
            assert_eq!(value, original);
        }
        for bad in [
            Value::Null,
            json!([]),
            json!({}),
            json!({"keys":null}),
            json!({"keys":{}}),
        ] {
            assert_eq!(
                validate_supplied(role, json!({"jwks":bad}).as_object().unwrap()),
                Err("jwks")
            );
        }
        for field in ["jwks_uri", "signed_jwks_uri"] {
            for bad in crate::oidc::provider_urls::test_contract::bad_endpoints() {
                assert_eq!(
                    validate_supplied(role, json!({(field):bad}).as_object().unwrap()),
                    Err(field)
                );
            }
        }
    }
    assert!(validate_supplied(
        "future_role",
        json!({"jwks":7,"signed_jwks_uri":false})
            .as_object()
            .unwrap()
    )
    .is_ok());
}

#[test]
fn public_profile_rejects_every_private_name_before_member_filtering() {
    for field in PRIVATE_MEMBERS {
        for value in [Value::Null, json!(false), json!("do-not-echo")] {
            for kty in ["RSA", "EC", "oct", "future"] {
                let input = json!({"keys":[{"kty":kty,(*field):value}]});
                let err = validate_public_jwks(&input).unwrap_err();
                assert!(!err.contains("do-not-echo"));
            }
        }
    }
    assert!(
        validate_public_jwks(&json!({"keys":[{"kty":"oct"},{"extension":{"d":"opaque"}}]})).is_ok()
    );
}
