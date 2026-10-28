use super::*;
use crate::web::upstream_metadata::federation::validate_upstream_jwks_matches_federation_metadata;
use serde_json::json;

fn key() -> Value {
    let signing = crate::oidc::OidcSigningKey::from_rsa_pem(
        "good".into(),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa2048-private.pk8.pem"
        )),
    )
    .unwrap();
    serde_json::to_value(signing.jwks()).unwrap()["keys"][0].clone()
}

#[test]
fn protocol_verification_tolerates_members_but_keeps_original_kid_and_profile() {
    let good = key();
    let raw = json!({"keys":[null,{"kid":"bad","kty":"unknown"},good]});
    let set = parse_upstream_jwks_body(&serde_json::to_vec(&raw).unwrap()).unwrap();
    assert_eq!(
        select_upstream_signing_key(&set, None).unwrap().kid(),
        Some("good")
    );
    for bad in [
        json!({"kid":"good","kty":"unknown"}),
        json!({"kty":"unknown","d":null}),
    ] {
        assert!(admit_upstream_jwks(&json!({"keys":[key(),bad]})).is_err());
    }
    for bad in [json!([]), json!([null,{}, {"kty":"future"}])] {
        assert!(admit_upstream_jwks(&json!({"keys":bad})).is_err());
    }
    for (field, value) in [
        ("alg", json!("rs256")),
        ("alg", Value::Null),
        ("use", json!("SIG")),
        ("use", Value::Null),
        ("key_ops", json!(["sign"])),
        ("n", json!("AA")),
    ] {
        let mut bad = key();
        bad[field] = value;
        bad["kid"] = json!("bad");
        let set = admit_upstream_jwks(&json!({"keys":[bad,key()]})).unwrap();
        assert!(select_upstream_signing_key(&set, Some("bad")).is_err());
    }
    // A visible extra cannot be smuggled via structural typed callers.
    let mut raw = key();
    raw["d"] = Value::Null;
    let typed = JwkSet::from_value(json!({"keys":[raw]})).unwrap();
    assert!(select_upstream_signing_key(&typed, None).is_err());
}

#[test]
fn protocol_inline_constraint_requires_equal_identities_and_algorithm_subset() {
    let restricted = key();
    let mut unrestricted = restricted.clone();
    unrestricted.as_object_mut().unwrap().remove("alg");
    let fetched = admit_upstream_jwks(&json!({"keys":[restricted.clone()]})).unwrap();
    assert!(validate_upstream_jwks_matches_federation_metadata(
        &fetched,
        &json!({"jwks":{"keys":[unrestricted.clone()]}})
    )
    .is_ok());
    let wider = admit_upstream_jwks(&json!({"keys":[unrestricted]})).unwrap();
    assert!(validate_upstream_jwks_matches_federation_metadata(
        &wider,
        &json!({"jwks":{"keys":[restricted.clone()]}})
    )
    .is_err());
    let mut missing = restricted.clone();
    missing.as_object_mut().unwrap().remove("kid");
    let mut empty = missing.clone();
    empty["kid"] = json!("");
    let no_kid = admit_upstream_jwks(&json!({"keys":[missing]})).unwrap();
    assert!(validate_upstream_jwks_matches_federation_metadata(
        &no_kid,
        &json!({"jwks":{"keys":[empty]}})
    )
    .is_err());
    let mut alternate = restricted.clone();
    alternate["kid"] = json!("other");
    alternate["alg"] = json!("RS384");
    let ambiguous = admit_upstream_jwks(&json!({"keys":[restricted,alternate]})).unwrap();
    assert!(select_upstream_signing_key(&ambiguous, None).is_err());
}

#[tokio::test]
async fn protocol_raw_cache_rechecks_public_profile_and_outbound_before_reuse() {
    let cache = NonAuthoritativeMetadataCache::new_non_authoritative();
    let uri = "https://example.com/jwks";
    let client = reqwest::Client::new();
    let coordinator = UpstreamJwksFetchCoordinator::default();
    let header = super::tests::header(Some("good"));
    let raw =
        json!({"keys":[key(),{"kty":"unknown","extension":{"nested":null}}],"extension":true});
    cache.try_insert(uri, raw.clone().into()).unwrap();
    assert!(fetch_upstream_jwks_cached(
        &client,
        uri,
        &cache,
        &coordinator,
        &header,
        &["example.com".into()],
        |_| std::future::ready(Err("unexpected cache fetch".into()))
    )
    .await
    .is_ok());
    assert_eq!(
        cache
            .try_get(uri)
            .unwrap()
            .map(|entry| entry.original().clone()),
        Some(raw)
    );
    assert!(fetch_upstream_jwks_cached(
        &client,
        uri,
        &cache,
        &coordinator,
        &header,
        &["denied.example".into()],
        |_| std::future::ready(Err("unexpected cache fetch".into()))
    )
    .await
    .is_err());
    cache
        .try_insert(
            uri,
            json!({"keys":[key(),{"kty":"unknown","d":null}]}).into(),
        )
        .unwrap();
    assert!(
        fetch_upstream_jwks_cached(&client, uri, &cache, &coordinator, &header, &[], |_| {
            std::future::ready(Err("unexpected cache fetch".into()))
        })
        .await
        .is_err()
    );
}

#[test]
fn protocol_ec_mixed_set_verifies_real_signature_and_rejects_other_key() {
    use crate::web::upstream_id_token::verify_upstream_id_token_claims;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let _guard = crate::util::RAW_JSON_ENV_GUARD.lock().unwrap();
    let generated = aegaeon_crypto::signing::EcdsaP256SigningKey::generate().unwrap();
    let signer =
        aegaeon_crypto::signing::EcdsaP256SigningKey::from_pkcs8(&generated.pkcs8).unwrap();
    let public = json!({"kty":"EC","kid":"ec","crv":"P-256","x":URL_SAFE_NO_PAD.encode(generated.public_x),"y":URL_SAFE_NO_PAD.encode(generated.public_y),"alg":"ES256"});
    let jwks = admit_upstream_jwks(&json!({"keys":[null,{"kty":"future"},public]})).unwrap();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"ec"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        br#"{"iss":"https://issuer.example","sub":"subject","aud":"client","iat":1,"exp":100}"#,
    );
    let input = format!("{header}.{payload}");
    let token = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signer.sign(input.as_bytes()).unwrap())
    );
    let mut discovery = crate::oidc::OidcDiscovery::new_with_runtime_config(
        "https://issuer.example",
        "https://issuer.example",
        &crate::metadata::MetadataRuntimeConfig::default(),
    );
    discovery.id_token_signing_alg_values_supported = vec!["RS256".into(), "ES256".into()];
    let (_, alg) = verify_upstream_id_token_claims(&token, &jwks, &discovery, 4096).unwrap();
    assert_eq!(alg, "ES256");
    let mut wrong = key();
    wrong["kid"] = json!("ec");
    let wrong = admit_upstream_jwks(&json!({"keys":[wrong]})).unwrap();
    assert!(verify_upstream_id_token_claims(&token, &wrong, &discovery, 4096).is_err());
}

#[tokio::test]
async fn protocol_warm_cache_reuses_admission_and_preserves_original_metadata() {
    let cache = NonAuthoritativeMetadataCache::new_non_authoritative();
    let uri = "https://example.com/jwks";
    let client = reqwest::Client::new();
    let coordinator = UpstreamJwksFetchCoordinator::default();
    let header = super::tests::header(Some("good"));
    let mut other = key();
    other["kid"] = json!("other");
    let raw = json!({"keys":[key(), other, {"kty":"unknown","kid":"unusable"}]});
    cache
        .try_insert(uri, CachedUpstreamJwks::from(raw.clone()))
        .unwrap();
    JWKS_ADMISSIONS.set(0);
    for _ in 0..3 {
        let view = fetch_upstream_jwks_cached(
            &client,
            uri,
            &cache,
            &coordinator,
            &header,
            &["example.com".into()],
            |_| std::future::ready(Err("unexpected network acquisition".into())),
        )
        .await
        .unwrap();
        assert_eq!(
            JWKS_ADMISSIONS.get(),
            1,
            "warm reuse repeated whole-set admission"
        );
        assert!(view.observed_kid("unusable"));
        assert_eq!(
            select_upstream_signing_key(&view, Some("good"))
                .unwrap()
                .kid(),
            Some("good")
        );
        let mut selected = select_upstream_signing_key(&view, Some("good"))
            .unwrap()
            .clone();
        selected.key_type = "invalid".into();
        assert!(!selected.is_verification_candidate());
        assert_eq!(cache.try_get(uri).unwrap().unwrap().original(), &raw);
    }
}
