use super::*;
use crate::client_registry::{
    jwks_refresh::refresh_jwks_with_state, jwks_validation::build_kid_fingerprints,
};

pub(in crate::client_registry::jwks_helpers_tests) fn guarded_pair(
    algorithm: Algorithm,
) -> (FetchedJwks, Value) {
    let (mut first, _) = material(algorithm);
    let (mut second, _) = material(algorithm);
    match algorithm {
        Algorithm::RS256 | Algorithm::PS256 => second["e"] = json!("Aw"),
        Algorithm::ES256 => {
            let fresh = aegaeon_crypto::signing::EcdsaP256SigningKey::generate().unwrap();
            second["x"] = json!(URL_SAFE_NO_PAD.encode(fresh.public_x));
            second["y"] = json!(URL_SAFE_NO_PAD.encode(fresh.public_y));
        }
        Algorithm::ES384 => {} // This fixture already generates a fresh key.
        _ => unreachable!(),
    }
    let field = if matches!(algorithm, Algorithm::RS256 | Algorithm::PS256) {
        "x"
    } else {
        "n"
    };
    first[field] = json!(5);
    second[field] = json!(["unrelated"]);
    (
        serde_json::from_value(json!({"keys":[first]})).unwrap(),
        json!({"keys":[second]}),
    )
}

#[test]
fn jwk_mixed_admitted_material_with_unrelated_extras_remains_in_local_guard() {
    let _env = env_lock().unwrap();
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    for algorithm in [Algorithm::RS256, Algorithm::ES256, Algorithm::ES384] {
        let (first, replacement) = guarded_pair(algorithm);
        let second: FetchedJwks = serde_json::from_value(replacement.clone()).unwrap();
        assert_eq!(first.keys().len(), 1);
        assert_eq!(second.keys().len(), 1);
        let original = build_kid_fingerprints(&first);
        assert_eq!(original.len(), 1);
        assert_ne!(original[KID], build_kid_fingerprints(&second)[KID]);
        let (uri, server) = super::super::super::owned_result_tests::response_fixture(
            200,
            serde_json::to_vec(&replacement).unwrap(),
            "max-age=300",
        );
        let registry = registry();
        assert!(!registry.jwks_policy.allow_kid_reuse);
        registry
            .jwks_state
            .inner
            .cache
            .lock()
            .unwrap()
            .insert(uri.clone(), cache_test_entry(first, Instant::now()));
        assert!(
            refresh_jwks_with_state(&registry.jwks_state, &registry.jwks_policy, &uri).is_none()
        );
        server.join().unwrap();
        assert_eq!(
            registry
                .jwks_state
                .inner
                .cache
                .lock()
                .unwrap()
                .get(&uri)
                .unwrap()
                .guard
                .kid_fps,
            original
        );
    }
}

fn counter(name: &str, labels: &[(&str, &str)]) -> f64 {
    prometheus::gather()
        .iter()
        .filter(|family| family.name() == name)
        .flat_map(|family| family.get_metric())
        .filter(|metric| {
            labels.iter().all(|(name, value)| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == *name && label.value() == *value)
            })
        })
        .map(|metric| metric.get_counter().value())
        .sum()
}

#[test]
fn jwk_mixed_http_duplicate_id_preserves_validation_metrics_and_refusal() {
    let _env = env_lock().unwrap();
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    let (key, _) = material(Algorithm::ES256);
    for duplicate in [key.clone(), json!({"kty":"OKP","kid":KID})] {
        let (uri, server) = super::super::super::owned_result_tests::response_fixture(
            200,
            serde_json::to_vec(&json!({"keys":[key,duplicate]})).unwrap(),
            "max-age=300",
        );
        let hash = sha256_hex(uri.as_bytes());
        let labels = [
            ("reason", "validation_duplicate_kid"),
            ("uri_hash", &hash[..8]),
        ];
        let before = counter("jwks_kid_duplicate_total", &[]);
        let reason_before = counter("jwks_http_failures_reason_total", &labels);
        let registry = registry();
        assert!(
            refresh_jwks_with_state(&registry.jwks_state, &registry.jwks_policy, &uri).is_none()
        );
        server.join().unwrap();
        assert!(counter("jwks_kid_duplicate_total", &[]) >= before + 1.0);
        assert_eq!(
            counter("jwks_http_failures_reason_total", &labels),
            reason_before + 1.0
        );
        assert_eq!(
            counter(
                "jwks_http_failures_reason_total",
                &[("reason", "json_parse"), ("uri_hash", &hash[..8])]
            ),
            0.0
        );
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
