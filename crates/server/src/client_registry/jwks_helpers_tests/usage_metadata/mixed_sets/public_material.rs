use super::*;
use crate::client_registry::{
    jwks_fetch_context::JwksFetchContext, jwks_fetch_memory::refresh_and_read_memory_cache,
    jwks_validation::build_kid_fingerprints,
};

#[test]
fn public_client_remote_secret_sibling_never_admits_body_or_guard() {
    let _env = env_lock().unwrap();
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    let (key, signer) = material(Algorithm::RS256);
    for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let mut sibling = json!({"kty":"unsupported", "kid":"private-sibling"});
        sibling[field] = Value::Null;
        let body = json!({"keys":[key,sibling]});
        let (uri, server) = super::super::super::owned_result_tests::response_fixture(
            200,
            serde_json::to_vec(&body).unwrap(),
            "max-age=300",
        );
        let registry = registry();
        assert!(registry.register(client(Algorithm::RS256, None, Some(uri.clone()))));
        assert!(!verify(
            &registry,
            &assertion(Algorithm::RS256, &signer),
            Algorithm::RS256
        ));
        server.join().unwrap();
        assert!(registry
            .jwks_state
            .inner
            .cache
            .lock()
            .unwrap()
            .get(&uri)
            .is_none());
    }
}

#[test]
fn public_client_remote_rejected_refresh_preserves_safe_body_and_guard() {
    let _env = env_lock().unwrap();
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    let (key, _) = material(Algorithm::RS256);
    let safe = FetchedJwks::from_value(&json!({"keys":[key]})).unwrap();
    let mut rejected = key.clone();
    rejected["d"] = json!("private-sentinel");
    let (uri, server) = super::super::super::owned_result_tests::response_fixture(
        200,
        serde_json::to_vec(&json!({"keys":[rejected]})).unwrap(),
        "max-age=300",
    );
    let registry = registry();
    let entry = cache_test_entry(safe.clone(), Instant::now());
    let before = entry.guard.clone();
    registry
        .jwks_state
        .inner
        .cache
        .lock()
        .unwrap()
        .insert(uri.clone(), entry);
    let context = JwksFetchContext::new(&registry.jwks_state, &registry.jwks_policy, &uri);
    let fallback = refresh_and_read_memory_cache(&context).unwrap();
    server.join().unwrap();
    assert_eq!(
        build_kid_fingerprints(&fallback),
        build_kid_fingerprints(&safe)
    );
    let cache = registry.jwks_state.inner.cache.lock().unwrap();
    let current = cache.get(&uri).unwrap();
    assert_eq!(current.guard.admitted_at, before.admitted_at);
    assert_eq!(current.guard.deadline, before.deadline);
}

#[test]
fn legacy_client_projection_preserves_actual_supported_signature_verification() {
    for algorithm in [
        Algorithm::RS256,
        Algorithm::PS256,
        Algorithm::ES256,
        Algorithm::ES384,
    ] {
        let (mut key, signer) = material(algorithm);
        key["d"] = json!("private-sentinel");
        key["k"] = Value::Null;
        let loaded = RegisteredClientJwks::from_stored_value(json!({"keys":[key]})).unwrap();
        let registry = registry();
        let mut registered = client(algorithm, None, None);
        registered.inline_jwks = Some(loaded);
        assert!(registry.register(registered));
        assert!(verify(&registry, &assertion(algorithm, &signer), algorithm));
    }
}
