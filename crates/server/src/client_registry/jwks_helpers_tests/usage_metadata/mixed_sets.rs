use super::algorithm_binding::verify;
use super::*;
use crate::test_utils::jwk_usage::{unusable_siblings, KID};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[test]
fn jwk_mixed_registry_real_signatures_survive_unusable_siblings_and_cache_hits() {
    let _env = env_lock().unwrap();
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    for algorithm in [
        Algorithm::RS256,
        Algorithm::PS256,
        Algorithm::ES256,
        Algorithm::ES384,
    ] {
        let (key, signer) = material(algorithm);
        let token = assertion(algorithm, &signer);
        for mut bad in unusable_siblings(&key) {
            // Client public sets reject secret-bearing siblings; this positive
            // mixed-set control retains unsupported public-only siblings.
            if let Some(object) = bad.as_object_mut() {
                object.remove("k");
            }
            for keys in [
                vec![key.clone(), bad.clone()],
                vec![bad.clone(), key.clone()],
            ] {
                let set = json!({"keys":keys});
                let (uri, server) = super::super::owned_result_tests::response_fixture(
                    200,
                    serde_json::to_vec(&set).unwrap(),
                    "max-age=300",
                );
                let remote = registry();
                assert!(remote.register(client(algorithm, None, Some(uri.clone()))));
                assert!(verify(&remote, &token, algorithm));
                server.join().unwrap();
                let cached = remote
                    .jwks_state
                    .inner
                    .cache
                    .lock()
                    .unwrap()
                    .get(&uri)
                    .unwrap()
                    .jwks
                    .clone();
                assert_eq!(cached.keys.len(), 1);
                assert!(select_jwk(&cached, None).is_some());
                assert!(select_jwk(&cached, Some("ignored")).is_none());
                // A fresh assertion has its own replay identifier; Request Objects
                // permit the same signature through the actual cache path.
                if !matches!(algorithm, Algorithm::RS256 | Algorithm::PS256) {
                    assert!(verify(&remote, &token, algorithm));
                }
                let mut pieces: Vec<String> = token.split('.').map(str::to_owned).collect();
                let mut signature = URL_SAFE_NO_PAD.decode(&pieces[2]).unwrap();
                signature[0] ^= 1;
                pieces[2] = URL_SAFE_NO_PAD.encode(signature);
                let corrupt = registry();
                corrupt.jwks_state.inner.cache.lock().unwrap().insert(
                    uri.clone(),
                    cache_test_entry(cached.clone(), Instant::now()),
                );
                assert!(corrupt.register(client(algorithm, None, Some(uri.clone()))));
                assert!(!verify(&corrupt, &pieces.join("."), algorithm));
            }
        }
    }
}

#[test]
fn jwk_mixed_inline_retains_original_value_and_reload_with_legacy_invalid_material() {
    let (key, signer) = material(Algorithm::RS256);
    let mut invalid = key.clone();
    invalid["kid"] = json!("legacy");
    invalid["n"] = json!("AA");
    let value = json!({"keys":[invalid,key]});
    let original = RegisteredClientJwks::from_value(value.clone(), true).unwrap();
    assert_eq!(original.as_value(), &value);
    let reloaded = RegisteredClientJwks::from_value(original.as_value().clone(), true).unwrap();
    assert!(reloaded.select(Some("legacy")).is_none());
    assert!(reloaded.select(None).is_some());
    let registry = registry();
    let mut registered = client(Algorithm::RS256, None, None);
    registered.inline_jwks = Some(reloaded);
    assert!(registry.register(registered));
    assert!(verify(
        &registry,
        &assertion(Algorithm::RS256, &signer),
        Algorithm::RS256
    ));
    let only_legacy = json!({"keys":[invalid]});
    let admitted = RegisteredClientJwks::from_value(only_legacy.clone(), true).unwrap();
    assert_eq!(admitted.as_value(), &only_legacy);
    assert!(admitted.select(None).is_none());
}

#[test]
fn jwk_mixed_original_duplicate_kids_and_algorithm_ambiguity_refuse_selection() {
    let (key, _) = material(Algorithm::RS256);
    for bad in [
        json!({"kty":"OKP","kid":KID}),
        json!({"kty":"RSA","kid":KID,"use":"enc","n":"AA","e":"AQAB"}),
    ] {
        assert!(serde_json::from_value::<FetchedJwks>(json!({"keys":[key,bad]})).is_err());
    }
    let (mut ec, _) = material(Algorithm::ES256);
    ec["kid"] = json!("ec");
    let set: FetchedJwks = serde_json::from_value(json!({"keys":[key,ec]})).unwrap();
    assert!(select_jwk(&set, None).is_none());
    assert!(select_jwk(&set, Some(KID)).is_some());
    let mut mutated = set.clone();
    mutated.keys[1].kid = Some(KID.into());
    assert!(select_jwk(&mutated, Some(KID)).is_none());
}

#[test]
fn jwk_mixed_legacy_fingerprints_survive_fixture_cache_and_failed_refresh_fallback() {
    use crate::client_registry::{
        jwks_fetch_context::JwksFetchContext,
        jwks_fetch_memory::refresh_and_read_memory_cache,
        jwks_validation::build_kid_fingerprints,
        jwks_validators::{DateContext, JwksValidators},
    };
    let _env = env_lock().unwrap();
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    let (key, _) = material(Algorithm::RS256);
    let rejected = json!({"kty":"RSA","kid":"rejected","n":"AA","e":"AQAB","x":null,"use":"enc"});
    let value = json!({"keys":[key,rejected,{"kty":"oct","kid":"wrong-type","n":5}],"legacy_fingerprints":{"rejected":"untrusted"}});
    let body: FetchedJwks = serde_json::from_value(value.clone()).unwrap();
    let map = build_kid_fingerprints(&body);
    assert_eq!(map.len(), 2);
    for member in value["keys"].as_array().unwrap().iter().take(2) {
        let public = ["kty", "n", "e", "x", "y"]
            .map(|field| member.get(field).and_then(Value::as_str).unwrap_or(""));
        assert_eq!(
            map[member["kid"].as_str().unwrap()],
            sha256_hex(public.join("|").as_bytes())
        );
    }
    assert_eq!(
        map,
        build_kid_fingerprints(
            &FetchedJwks::from_fixture_bytes(&body.to_fixture_bytes().unwrap()).unwrap()
        )
    );
    assert!(serde_json::to_value(&body)
        .unwrap()
        .get("legacy_fingerprints")
        .is_none());
    // The 304 deliberately omits a returned validator. It is unusable;
    // its unconditional retry reaches the closed one-shot fixture, so this
    // exercises fallback, not successful network revalidation.
    for status in [304, 503, 200] {
        let incoming = if status == 200 {
            let mut changed = value.clone();
            changed["keys"][1]["n"] = json!("AQ");
            serde_json::to_vec(&changed).unwrap()
        } else {
            Vec::new()
        };
        let (uri, server) =
            super::super::owned_result_tests::response_fixture(status, incoming, "max-age=300");
        let registry = registry();
        let mut entry = cache_test_entry(body.clone(), Instant::now());
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::ETAG, HeaderValue::from_static("\"mixed\""));
        entry.validators = JwksValidators::from_headers(&headers, DateContext::capture());
        entry.effective_target = Some(uri.clone());
        let deadline = entry.guard.deadline;
        let admitted_at = entry.guard.admitted_at;
        registry
            .jwks_state
            .inner
            .cache
            .lock()
            .unwrap()
            .insert(uri.clone(), entry);
        let cached =
            fetch_jwks_with_state(&registry.jwks_state, &registry.jwks_policy, &uri).unwrap();
        assert_eq!(build_kid_fingerprints(&cached), map);
        let context = JwksFetchContext::new(&registry.jwks_state, &registry.jwks_policy, &uri);
        let outcome = refresh_and_read_memory_cache(&context).unwrap();
        assert_eq!(build_kid_fingerprints(&outcome), map);
        assert!(select_jwk(&outcome, Some("rejected")).is_none());
        let request = server.join().unwrap();
        assert!(request
            .to_ascii_lowercase()
            .contains("if-none-match: \"mixed\""));
        let cache = registry.jwks_state.inner.cache.lock().unwrap();
        let current = cache.get(&uri).unwrap();
        assert_eq!(current.guard.deadline, deadline);
        assert_eq!(current.guard.admitted_at, admitted_at);
        assert_eq!(build_kid_fingerprints(&current.jwks), map);
    }
}

#[test]
fn jwk_mixed_remote_rejects_duplicate_names_in_ignored_members_and_trailing_bytes() {
    let _env = env_lock().unwrap();
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    let (key, _) = material(Algorithm::RS256);
    for body in [
        format!("{{\"keys\":[{key},{{\"kty\":\"oct\",\"extra\":{{\"nested\":1,\"nested\":2}}}}]}}"),
        format!("{{\"keys\":[{key}]}} trailing"),
        json!({"keys":null}).to_string(),
        json!({"keys":[{"kty":"oct","kid":"unusable"}]}).to_string(),
    ] {
        let (uri, server) = super::super::owned_result_tests::response_fixture(
            200,
            body.into_bytes(),
            "max-age=300",
        );
        let registry = registry();
        assert!(fetch_jwks_with_state(&registry.jwks_state, &registry.jwks_policy, &uri).is_none());
        server.join().unwrap();
        assert!(!registry
            .jwks_state
            .inner
            .cache
            .lock()
            .unwrap()
            .contains_key(&uri));
    }
}

mod revalidation;

mod public_material;
