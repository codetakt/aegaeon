use super::*;
use crate::client_registry::{
    jwks_fetch_context::JwksFetchContext, jwks_fetch_memory::probe_memory_cache,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tracing_subscriber::{
    layer::{Context, Layer},
    prelude::*,
};

struct MaterialProbe {
    state: JwksRuntimeState,
    parses: Arc<AtomicUsize>,
}

impl<S: tracing::Subscriber> Layer<S> for MaterialProbe {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() == "jwks_material_validation" {
            assert!(
                self.state.inner.cache.try_lock().is_ok(),
                "material validation holds cache mutex"
            );
            self.parses.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[test]
fn jwk_mixed_cache_admission_is_immutable_and_material_checks_leave_mutex_free() {
    let registry = registry();
    let (key, _) = material(Algorithm::RS256);
    let admitted: FetchedJwks = serde_json::from_value(json!({"keys":[key]})).unwrap();
    let parses = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(MaterialProbe {
        state: registry.jwks_state.clone(),
        parses: parses.clone(),
    });
    tracing::subscriber::with_default(subscriber, || {
        let uri = "https://keys.example/jwks";
        registry.jwks_state.inner.cache.lock().unwrap().insert(
            uri.into(),
            cache_test_entry(admitted.clone(), Instant::now()),
        );
        let ctx = JwksFetchContext::new(&registry.jwks_state, &registry.jwks_policy, uri);
        for _ in 0..3 {
            let hit = probe_memory_cache(&ctx).hit.expect("admitted cache hit");
            assert!(select_jwk(&hit, Some(KID)).is_some());
            assert!(select_jwk(&hit, Some("missing")).is_none());
        }
        assert_eq!(
            parses.load(Ordering::SeqCst),
            0,
            "cache selection reparsed admitted material"
        );
        let mut mutated = admitted.clone();
        mutated.keys_mut_for_tests()[0].n = Some("AA".into());
        registry.jwks_state.inner.cache.lock().unwrap().insert(
            uri.into(),
            cache_test_entry(mutated.clone(), Instant::now()),
        );
        assert!(probe_memory_cache(&ctx).hit.is_none());
        assert!(select_jwk(&mutated, Some(KID)).is_none());
        assert_eq!(parses.load(Ordering::SeqCst), 2);
        assert!(
            select_jwk(&admitted, Some(KID)).is_some(),
            "mutation changed immutable clone"
        );
        let restored =
            FetchedJwks::from_fixture_bytes(&admitted.to_fixture_bytes().unwrap()).unwrap();
        assert!(select_jwk(&restored, Some(KID)).is_some());
        assert_eq!(
            parses.load(Ordering::SeqCst),
            3,
            "fixture bytes cannot grant admission"
        );
    });
}
