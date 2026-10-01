use super::*;
use crate::test_utils::jwk_usage::material;
use jsonwebtoken::Algorithm;
use serde_json::json;

#[test]
fn jwk_mixed_federation_metadata_matches_identity_and_limits_effective_algorithms() {
    let (mut key, _) = material(Algorithm::RS256);
    let exact = key.clone();
    key.as_object_mut().unwrap().remove("alg");
    let fetched = |key: Value| {
        JwkSet::from_verification_value(json!({"keys":[key,{"kty":"oct","kid":"ignored"}]}))
            .unwrap()
    };
    assert!(validate_upstream_jwks_matches_federation_metadata(
        &fetched(exact.clone()),
        &json!({"jwks":{"keys":[key,{"kty":"OKP","kid":"another"}]}})
    )
    .is_ok());
    assert!(validate_upstream_jwks_matches_federation_metadata(
        &fetched(key.clone()),
        &json!({"jwks":{"keys":[exact]}})
    )
    .is_err());
    let mut different = exact.clone();
    different["alg"] = json!("PS256");
    assert!(validate_upstream_jwks_matches_federation_metadata(
        &fetched(different),
        &json!({"jwks":{"keys":[exact]}})
    )
    .is_err());
    let mut missing = key.clone();
    missing.as_object_mut().unwrap().remove("kid");
    let mut empty = missing.clone();
    empty["kid"] = json!("");
    assert!(validate_upstream_jwks_matches_federation_metadata(
        &fetched(missing),
        &json!({"jwks":{"keys":[empty]}})
    )
    .is_err());
    let set = fetched(key.clone());
    assert!(validate_upstream_jwks_matches_federation_metadata(&set, &json!({})).is_ok());
    for value in [
        Value::Null,
        json!({}),
        json!({"keys":[]}),
        json!({"keys":[{"kty":"oct"}]}),
        json!({"keys":[key,{"kid":key["kid"],"kty":"OKP"}]}),
    ] {
        assert!(
            validate_upstream_jwks_matches_federation_metadata(&set, &json!({"jwks":value}))
                .is_err()
        );
    }
    let duplicate =
        JwkSet::from_verification_value(json!({"keys":[key,{"kid":key["kid"],"kty":"OKP"}]}))
            .unwrap();
    assert!(validate_upstream_jwks_matches_federation_metadata(
        &duplicate,
        &json!({"jwks":{"keys":[key]}})
    )
    .is_err());
}

#[test]
fn jwk_mixed_metadata_repeated_no_kid_identities_aggregate_algorithms_without_order_bias() {
    let (mut rsa, _) = material(Algorithm::RS256);
    rsa.as_object_mut().unwrap().remove("kid");
    let mut pss = rsa.clone();
    pss["alg"] = json!("PS256");
    let mut unrestricted = rsa.clone();
    unrestricted.as_object_mut().unwrap().remove("alg");
    for keys in [
        vec![rsa.clone(), pss.clone()],
        vec![pss.clone(), rsa.clone()],
    ] {
        let repeated = JwkSet::from_verification_value(json!({"keys":keys})).unwrap();
        assert!(repeated.select_verification_key(None).unwrap().is_none());
        assert!(validate_upstream_jwks_matches_federation_metadata(
            &repeated,
            &json!({"jwks":{"keys":[unrestricted]}})
        )
        .is_ok());
        for key in [&rsa, &pss] {
            let fetched = JwkSet::from_verification_value(json!({"keys":[key]})).unwrap();
            assert!(validate_upstream_jwks_matches_federation_metadata(
                &fetched,
                &json!({"jwks":{"keys":keys}})
            )
            .is_ok());
            assert!(validate_upstream_jwks_matches_federation_metadata(
                &repeated,
                &json!({"jwks":{"keys":[key]}})
            )
            .is_err());
        }
        let fetched = JwkSet::from_verification_value(json!({"keys":[unrestricted]})).unwrap();
        assert!(validate_upstream_jwks_matches_federation_metadata(
            &fetched,
            &json!({"jwks":{"keys":keys}})
        )
        .is_err());
    }
}
