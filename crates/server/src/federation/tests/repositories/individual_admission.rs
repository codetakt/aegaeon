use super::*;
use crate::federation::FederationFetchFuture as RepositoryFuture;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const NOW: i64 = 1_800_000_000;
const ENTITY: &str = "https://rp.example";
const AUTHORITY: &str = "https://ta.example";

#[derive(Default)]
struct Observations {
    gets: Vec<(Uuid, String, i64)>,
    writes: Vec<(Uuid, String, String, Value, i64)>,
}
struct Repository {
    row: Option<StoredEntityCache>,
    get_error: bool,
    write_error: bool,
    observations: Arc<Mutex<Observations>>,
}
impl EntityCacheRepository for Repository {
    fn get<'a>(
        &'a self,
        environment: Uuid,
        entity: &'a str,
        now: i64,
    ) -> RepositoryFuture<'a, Option<StoredEntityCache>> {
        Box::pin(async move {
            must_ok(self.observations.lock())
                .gets
                .push((environment, entity.into(), now));
            if self.get_error {
                return Err(FederationError::Storage("get failed".into()));
            }
            Ok(self.row.clone())
        })
    }
    fn upsert<'a>(
        &'a self,
        environment: Uuid,
        entity: &'a str,
        raw: &'a str,
        parsed: &'a Value,
        expiry: i64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            must_ok(self.observations.lock()).writes.push((
                environment,
                entity.into(),
                raw.into(),
                parsed.clone(),
                expiry,
            ));
            if self.write_error {
                return Err(FederationError::Storage("write failed".into()));
            }
            Ok(())
        })
    }
    fn cleanup_expired(&self, _: i64) -> RepositoryFuture<'_, u64> {
        Box::pin(async { Ok(0) })
    }
}
struct Callback {
    raw: Option<String>,
    typed: EntityStatement,
    calls: Arc<AtomicUsize>,
    fail: bool,
}
impl FederationFetcher for Callback {
    fn fetch_entity_configuration<'a>(
        &'a self,
        _: &'a str,
    ) -> FederationFetchFuture<'a, EntityStatement> {
        Box::pin(async {
            Err(FederationError::Fetch(
                "typed callback must not be used".into(),
            ))
        })
    }
    fn fetch_entity_configuration_with_jws<'a>(
        &'a self,
        _: &'a str,
    ) -> FederationFetchFuture<'a, FetchedEntityConfiguration> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(FederationError::Fetch("fetch failed".into()));
            }
            Ok(FetchedEntityConfiguration {
                statement: self.typed.clone(),
                entity_configuration_jws: self.raw.clone(),
            })
        })
    }
    fn fetch_subordinate_statement<'a>(
        &'a self,
        _: &'a str,
        _: &'a EntityStatement,
        _: &'a str,
        _: &'a JwkSet,
    ) -> FederationFetchFuture<'a, EntityStatement> {
        Box::pin(async {
            Err(FederationError::Fetch(
                "typed callback must not be used".into(),
            ))
        })
    }
    fn fetch_subordinate_statement_with_jws<'a>(
        &'a self,
        _: &'a str,
        _: &'a EntityStatement,
        _: &'a str,
        _: &'a JwkSet,
    ) -> FederationFetchFuture<'a, FetchedSubordinateStatement> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(FetchedSubordinateStatement {
                statement: self.typed.clone(),
                subordinate_statement_jws: self.raw.clone(),
            })
        })
    }
}
fn clock(samples: Vec<i64>) -> impl Fn() -> Result<i64, FederationError> {
    let index = AtomicUsize::new(0);
    move || {
        samples
            .get(index.fetch_add(1, Ordering::SeqCst))
            .copied()
            .ok_or_else(|| FederationError::Internal("test clock exhausted".into()))
    }
}
struct Fixture {
    environment: Uuid,
    statement: EntityStatement,
    raw: String,
    row: StoredEntityCache,
    observations: Arc<Mutex<Observations>>,
    calls: Arc<AtomicUsize>,
}
impl Fixture {
    fn new() -> Self {
        let environment = Uuid::new_v4();
        let statement = sample_entity_config(ENTITY, NOW);
        let raw = sign_entity_statement_for_test(sample_signing_key(), &statement);
        let row = StoredEntityCache {
            id: Uuid::new_v4(),
            environment_id: environment,
            entity_id: ENTITY.into(),
            entity_configuration_jws: raw.clone(),
            parsed_statement: json!({"forged": true}),
            fetched_at: NOW,
            expires_at: statement.exp,
        };
        Self {
            environment,
            statement,
            raw,
            row,
            observations: Arc::default(),
            calls: Arc::default(),
        }
    }
    fn fetcher(
        &self,
        row: Option<StoredEntityCache>,
        raw: Option<String>,
        get_error: bool,
        write_error: bool,
        fail: bool,
        ttl: u64,
    ) -> CachedFederationFetcher<Callback> {
        let mut forged = self.statement.clone();
        forged.iss = "https://forged.example".into();
        forged.sub = forged.iss.clone();
        forged.exp = i64::MAX;
        forged.metadata = Some(HashMap::from([(
            "openid_relying_party".into(),
            json!({"forged": true}),
        )]));
        CachedFederationFetcher::new(
            Callback {
                raw,
                typed: forged,
                calls: self.calls.clone(),
                fail,
            },
            Box::new(Repository {
                row,
                get_error,
                write_error,
                observations: self.observations.clone(),
            }),
            self.environment,
            &FederationCacheConfig {
                entity_cache_ttl: Duration::from_secs(ttl),
                ..FederationCacheConfig::default()
            },
        )
    }
}

#[test]
fn individual_cache_canonicalizes_miss_and_caps_expiry_despite_write_error() {
    let _guard = raw_json_env_guard();
    for write_error in [false, true] {
        let f = Fixture::new();
        let fetcher = f.fetcher(None, Some(f.raw.clone()), false, write_error, false, 10000);
        let result = must_ok(block_on_test_future(
            fetcher.fetch_entity_configuration_with_clock(ENTITY, clock(vec![NOW; 4])),
        ));
        assert_eq!(
            must_ok(serde_json::to_value(result)),
            must_ok(serde_json::to_value(&f.statement))
        );
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        let o = must_ok(f.observations.lock());
        assert_eq!(o.gets, vec![(f.environment, ENTITY.into(), NOW)]);
        assert_eq!(
            o.writes,
            vec![(
                f.environment,
                ENTITY.into(),
                f.raw.clone(),
                must_ok(serde_json::to_value(&f.statement)),
                f.statement.exp
            )]
        );
    }
}

#[test]
fn individual_cache_invalid_scope_lifetime_or_raw_refetches_without_stale_fallback() {
    let _guard = raw_json_env_guard();
    for mutation in 0..6 {
        for fail in [false, true] {
            let f = Fixture::new();
            let mut row = f.row.clone();
            match mutation {
                0 => row.environment_id = Uuid::new_v4(),
                1 => row.entity_id = "https://other.example".into(),
                2 => row.expires_at = NOW,
                3 => row.entity_configuration_jws = "bad".into(),
                4 => {
                    row.entity_configuration_jws = sign_entity_statement_for_test(
                        sample_signing_key(),
                        &sample_entity_config("https://other.example", NOW),
                    )
                }
                _ => {
                    row.entity_configuration_jws = sign_entity_statement_for_test(
                        sample_signing_key(),
                        &sample_entity_config(ENTITY, NOW - 10000),
                    )
                }
            }
            let fetcher = f.fetcher(Some(row), Some(f.raw.clone()), false, false, fail, 100);
            let result = block_on_test_future(
                fetcher.fetch_entity_configuration_with_clock(ENTITY, clock(vec![NOW; 4])),
            );
            assert_eq!(result.is_ok(), !fail);
            assert_eq!(f.calls.load(Ordering::SeqCst), 1);
            let o = must_ok(f.observations.lock());
            assert_eq!(o.writes.len(), usize::from(!fail));
            if !fail {
                assert_eq!(o.writes[0].4, NOW + 100);
            }
        }
    }
}

#[test]
fn individual_cache_valid_hit_ignores_parsed_and_never_calls_callback() {
    let _guard = raw_json_env_guard();
    let f = Fixture::new();
    let fetcher = f.fetcher(Some(f.row.clone()), None, false, false, true, 100);
    let result = must_ok(block_on_test_future(
        fetcher.fetch_entity_configuration_with_clock(ENTITY, clock(vec![NOW; 2])),
    ));
    assert_eq!(result.metadata, f.statement.metadata);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    assert!(must_ok(f.observations.lock()).writes.is_empty());
}

#[test]
fn individual_cache_missing_or_bad_raw_and_get_error_never_write() {
    let _guard = raw_json_env_guard();
    for mode in 0..4 {
        let f = Fixture::new();
        let raw = match mode {
            0 => None,
            1 => Some("bad".into()),
            2 => Some(sign_entity_statement_for_test(
                sample_signing_key(),
                &sample_entity_config("https://other.example", NOW),
            )),
            _ => Some(f.raw.clone()),
        };
        let fetcher = f.fetcher(None, raw, mode == 3, false, false, 100);
        assert!(block_on_test_future(
            fetcher.fetch_entity_configuration_with_clock(ENTITY, clock(vec![NOW; 4]))
        )
        .is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), usize::from(mode != 3));
        assert!(must_ok(f.observations.lock()).writes.is_empty());
    }
}

#[test]
fn individual_cache_resamples_after_get_fetch_and_upsert() {
    let _guard = raw_json_env_guard();
    for stage in 0..3 {
        let f = Fixture::new();
        let later = f.statement.exp + 61;
        let row = (stage == 0).then(|| f.row.clone());
        let samples = match stage {
            0 => vec![NOW, later, later],
            1 => vec![NOW, NOW, later],
            _ => vec![NOW, NOW, NOW, later],
        };
        let fetcher = f.fetcher(row, Some(f.raw.clone()), false, false, false, 100);
        assert!(block_on_test_future(
            fetcher.fetch_entity_configuration_with_clock(ENTITY, clock(samples))
        )
        .is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            must_ok(f.observations.lock()).writes.len(),
            usize::from(stage == 2)
        );
    }
    let f = Fixture::new();
    let fetcher = f.fetcher(None, Some(f.raw.clone()), false, false, false, 100);
    assert!(block_on_test_future(
        fetcher.fetch_entity_configuration_with_clock(ENTITY, clock(vec![NOW]))
    )
    .is_err());
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn individual_cache_does_not_store_zero_ttl_or_expired_skew_result() {
    let _guard = raw_json_env_guard();
    for skew in [false, true] {
        let f = Fixture::new();
        let now = if skew { f.statement.exp + 1 } else { NOW };
        let fetcher = f.fetcher(
            None,
            Some(f.raw.clone()),
            false,
            false,
            false,
            if skew { 100 } else { 0 },
        );
        assert!(block_on_test_future(
            fetcher.fetch_entity_configuration_with_clock(ENTITY, clock(vec![now; 3]))
        )
        .is_ok());
        assert!(must_ok(f.observations.lock()).writes.is_empty());
    }
}

#[test]
fn individual_subordinate_wrapper_checks_authority_before_callback_and_after_await() {
    let _guard = raw_json_env_guard();
    for mode in 0..7 {
        let f = Fixture::new();
        let mut authority = sample_entity_config(AUTHORITY, NOW);
        // This discovery key is deliberately different from the endorsed signing key.
        authority.jwks = Some(federation_jwks_value(&InMemoryKeyManager::new()));
        match mode {
            1 => authority.sub = ENTITY.into(),
            2 => authority.iat = NOW + 61,
            3 => authority.jwks = None,
            5 => authority.exp = NOW + 10,
            _ => {}
        }
        let raw = (mode != 4).then(|| {
            sign_entity_statement_for_test(
                sample_signing_key(),
                &sample_subordinate_statement(AUTHORITY, ENTITY, NOW),
            )
        });
        let fetcher = f.fetcher(None, raw, false, false, false, 100);
        let keys = if mode == 6 {
            must_ok(JwkSet::from_value(must_some(authority.jwks.clone())))
        } else {
            sample_jwks()
        };
        let samples = vec![NOW, if mode == 5 { authority.exp + 61 } else { NOW }];
        let result = block_on_test_future(fetcher.fetch_subordinate_statement_with_clock(
            AUTHORITY,
            &authority,
            ENTITY,
            &keys,
            clock(samples),
        ));
        assert_eq!(result.is_ok(), mode == 0, "mode {mode}");
        if let Ok(statement) = result {
            assert_eq!(statement.iss, AUTHORITY);
            assert_eq!(statement.sub, ENTITY);
        }
        assert_eq!(
            f.calls.load(Ordering::SeqCst),
            usize::from(!matches!(mode, 1..=3))
        );
        assert!(must_ok(f.observations.lock()).writes.is_empty());
    }
}

#[test]
fn individual_metadata_schema_rejects_raw_cache_and_fresh_values_before_storage() {
    let _guard = raw_json_env_guard();
    for metadata in [
        json!({"federation_entity":{"jwks_uri":"https://private.example/keys"}}),
        json!({"federation_entity":{"endpoint_auth_signing_alg_values_supported":["none"]}}),
        json!({"extension":{"contacts":[]}}),
        json!({"extension":{"logo_uri":"relative"}}),
    ] {
        for cached in [false, true] {
            for valid_fresh in [false, true] {
                let f = Fixture::new();
                let mut invalid = f.statement.clone();
                invalid.metadata = Some(must_ok(serde_json::from_value(metadata.clone())));
                let raw = sign_entity_statement_for_test(sample_signing_key(), &invalid);
                let mut row = f.row.clone();
                row.entity_configuration_jws = raw.clone();
                let fetcher = f.fetcher(
                    cached.then_some(row),
                    Some(if valid_fresh { f.raw.clone() } else { raw }),
                    false,
                    false,
                    false,
                    100,
                );
                let result = block_on_test_future(
                    fetcher.fetch_entity_configuration_with_clock(ENTITY, clock(vec![NOW; 4])),
                );
                assert_eq!(result.is_ok(), valid_fresh);
                assert_eq!(f.calls.load(Ordering::SeqCst), 1);
                let observed = must_ok(f.observations.lock());
                assert_eq!(observed.writes.len(), usize::from(valid_fresh));
                if valid_fresh {
                    assert_eq!(observed.writes[0].2, f.raw);
                }
            }
        }
    }
}
