use super::*;
use crate::web::upstream_id_token::admit_upstream_id_token_header;
use crate::web::upstream_metadata::{build_upstream_http_client, test_support::*};
use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

fn keyset(kid: &str) -> String {
    json!({"keys":[{"kty":"RSA","kid":kid,"use":"sig","alg":"RS256","n":"AQAB","e":"AQAB"}]})
        .to_string()
}
fn header(kid: Option<&str>) -> AdmittedUpstreamIdTokenHeader {
    let token = format!(
        "{}.e30.c2ln",
        URL_SAFE_NO_PAD.encode(json!({"alg":"RS256","kid":kid}).to_string())
    );
    admit_upstream_id_token_header(
        &token,
        &crate::web::upstream_tests::base_discovery("https://issuer.example").expect("discovery"),
        4096,
    )
    .expect("admitted header")
}
#[derive(Clone)]
struct Harness {
    cache: Arc<NonAuthoritativeMetadataCache<JwkSet>>,
    coordinator: Arc<UpstreamJwksFetchCoordinator>,
    client: Client,
}
impl Harness {
    fn new(clock: &ManualClock, max_entries: usize, ttl: u64) -> Self {
        Self {
            cache: Arc::new(
                NonAuthoritativeMetadataCache::with_ttl_secs_and_max_entries(ttl, max_entries),
            ),
            coordinator: Arc::new(clock.coordinator()),
            client: build_upstream_http_client(&[]).expect("client"),
        }
    }
    async fn get(&self, url: &str, kid: Option<&str>) -> Result<JwkSet, String> {
        fetch_upstream_jwks_cached(
            &self.client,
            url,
            &self.cache,
            &self.coordinator,
            &header(kid),
            &[],
        )
        .await
    }
    fn spawn(&self, url: String, kid: String) -> tokio::task::JoinHandle<Result<JwkSet, String>> {
        let this = self.clone();
        tokio::spawn(async move { this.get(&url, Some(&kid)).await })
    }
}

#[tokio::test]
async fn upstream_jwks_refresh_cold_cooldown_and_replacement() -> TestResult {
    let server = HttpFixture::new(keyset("old")).await?;
    let clock = ManualClock::new();
    let h = Harness::new(&clock, 2, 60);
    assert!(!header(Some("old")).unfamiliar_kid(&h.get(&server.url, Some("old")).await?));
    server.respond(StatusCode::OK, keyset("new"));
    assert!(header(Some("new")).unfamiliar_kid(&h.get(&server.url, Some("new")).await?));
    clock.advance(29_999);
    assert!(header(Some("new")).unfamiliar_kid(&h.get(&server.url, Some("new")).await?));
    assert_eq!(server.hits(), 1);
    clock.advance(1);
    let new = h.get(&server.url, Some("new")).await?;
    assert!(!header(Some("new")).unfamiliar_kid(&new));
    assert!(header(Some("old")).unfamiliar_kid(&new));
    assert_eq!(server.hits(), 2);
    let absent = h.get(&server.url, Some("old")).await?;
    assert!(header(Some("old")).unfamiliar_kid(&absent));
    assert_eq!(server.hits(), 2);
    Ok(())
}

#[tokio::test]
async fn upstream_jwks_refresh_same_url_coalesces_distinct_kids() -> TestResult {
    let server = HttpFixture::new(keyset("new")).await?;
    server.state.hold.store(true, Ordering::SeqCst);
    let clock = ManualClock::new();
    let h = Harness::new(&clock, 2, 60);
    let mut requests = vec![];
    for n in 0..24 {
        requests.push(h.spawn(server.url.clone(), format!("unknown-{n}")));
    }
    server.wait_hits(1).await?;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(server.hits(), 1);
    server.state.release.add_permits(1);
    for request in requests {
        assert!(request.await?.is_ok());
    }
    assert_eq!(server.hits(), 1);
    assert!(header(Some("still-missing"))
        .unfamiliar_kid(&h.get(&server.url, Some("still-missing")).await?));
    assert_eq!(server.hits(), 1);
    clock.advance(30_000);
    let mut warm = vec![];
    for n in 0..24 {
        warm.push(h.spawn(server.url.clone(), format!("warm-unknown-{n}")));
    }
    server.wait_hits(2).await?;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(server.hits(), 2);
    server.state.release.add_permits(1);
    for request in warm {
        assert!(request.await?.is_ok());
    }
    assert_eq!(server.hits(), 2);
    Ok(())
}

#[tokio::test]
async fn upstream_jwks_refresh_unrelated_urls_progress_and_capacity_fails_closed() -> TestResult {
    let a = HttpFixture::new(keyset("a")).await?;
    let b = HttpFixture::new(keyset("b")).await?;
    let c = HttpFixture::new(keyset("c")).await?;
    a.state.hold.store(true, Ordering::SeqCst);
    let clock = ManualClock::new();
    let h = Harness::new(&clock, 2, 60);
    let blocked = h.spawn(a.url.clone(), "a".into());
    a.wait_hits(1).await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), h.get(&b.url, Some("b")))
            .await?
            .is_ok()
    );
    assert!(h.get(&c.url, Some("c")).await.is_err());
    assert_eq!(c.hits(), 0);
    // Hits need no coordinator admission, even when every retained slot is protected.
    h.cache
        .try_insert(&c.url, parse_upstream_jwks_body(keyset("c").as_bytes())?)?;
    assert!(h.get(&c.url, Some("c")).await.is_ok());
    assert_eq!(c.hits(), 0);
    clock.advance(30_000);
    assert!(h.get(&c.url, Some("different")).await.is_ok());
    assert_eq!(c.hits(), 1);
    // Pruning the idle b slot must not evict the still-in-flight a slot.
    assert_eq!(a.hits(), 1);
    a.state.release.add_permits(1);
    assert!(blocked.await?.is_ok());
    Ok(())
}

#[tokio::test]
async fn upstream_jwks_refresh_cancellation_and_timeout_retain_attempt_start() -> TestResult {
    let server = HttpFixture::new(keyset("new")).await?;
    server.state.hold.store(true, Ordering::SeqCst);
    let clock = ManualClock::new();
    let mut h = Harness::new(&clock, 1, 60);
    let request = h.spawn(server.url.clone(), "new".into());
    server.wait_hits(1).await?;
    request.abort();
    assert!(request.await.expect_err("cancelled request").is_cancelled());
    assert!(h.get(&server.url, Some("new")).await.is_err());
    assert_eq!(server.hits(), 1);
    clock.advance(30_000);
    h.client = Client::builder()
        .timeout(Duration::from_millis(40))
        .build()?;
    assert!(h.get(&server.url, Some("new")).await.is_err());
    assert_eq!(server.hits(), 2);
    assert!(h.get(&server.url, Some("new")).await.is_err());
    assert_eq!(server.hits(), 2);
    server.state.hold.store(false, Ordering::SeqCst);
    server.state.release.add_permits(2);
    clock.advance(30_000);
    assert!(h.get(&server.url, Some("new")).await.is_ok());
    assert_eq!(server.hits(), 3);
    Ok(())
}

#[tokio::test]
async fn upstream_jwks_refresh_failures_preserve_fresh_set_without_extending_ttl() -> TestResult {
    let server = HttpFixture::new(keyset("old")).await?;
    let clock = ManualClock::new();
    let h = Harness::new(&clock, 1, 2);
    h.get(&server.url, Some("old")).await?;
    let invalid = [
        "{\"keys\":[],\"keys\":[]}".to_string(),
        "not-json".into(),
        "{\"keys\":[{}]}".into(),
        "x".repeat(UPSTREAM_MAX_BODY_BYTES + 1),
    ];
    for body in invalid {
        clock.advance(30_000);
        server.respond(StatusCode::OK, body);
        assert!(h.get(&server.url, Some("new")).await.is_err());
        assert!(
            !header(Some("old")).unfamiliar_kid(&h.cache.try_get(&server.url)?.ok_or("old set")?)
        );
    }
    clock.advance(30_000);
    server.respond(StatusCode::INTERNAL_SERVER_ERROR, "upstream failure".into());
    assert!(h.get(&server.url, Some("new")).await.is_err());
    // Fail again after the original TTL is partly consumed, so a mistaken renewal
    // would still be fresh at the final assertion below.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    clock.advance(30_000);
    server.respond(
        StatusCode::OK,
        json!({"keys":[{"kty":"RSA","kid":"new","n":"","e":"AQAB"}]}).to_string(),
    );
    assert!(h
        .get(&server.url, Some("new"))
        .await
        .expect_err("malformed material")
        .contains("key material encoding invalid"));
    let hits = server.hits();
    assert!(h.get(&server.url, Some("old")).await.is_ok());
    assert_eq!(server.hits(), hits);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(h.cache.try_get(&server.url)?.is_none());
    assert!(h.get(&server.url, Some("old")).await.is_err());
    assert_eq!(server.hits(), hits);
    Ok(())
}

#[tokio::test]
async fn upstream_jwks_refresh_rechecks_cached_endpoint_policy() -> TestResult {
    let clock = ManualClock::new();
    let h = Harness::new(&clock, 1, 60);
    let urls = [
        "http://192.0.2.1/keys",
        "https://127.0.0.1/keys",
        "https://user:password@example.com/keys",
        "https://issuer.example/keys#fragment",
    ];
    for url in urls {
        h.cache
            .try_insert(url, parse_upstream_jwks_body(keyset("known").as_bytes())?)?;
        assert!(h.get(url, Some("known")).await.is_err());
    }
    let url = "https://example.com/keys";
    h.cache
        .try_insert(url, parse_upstream_jwks_body(keyset("known").as_bytes())?)?;
    assert!(fetch_upstream_jwks_cached(
        &h.client,
        url,
        &h.cache,
        &h.coordinator,
        &header(Some("known")),
        &["allowed.example".into()]
    )
    .await
    .is_err());
    Ok(())
}

#[test]
fn upstream_jwks_refresh_pruning_cannot_split_waiter_slot_or_query_identity() -> TestResult {
    let clock = ManualClock::new();
    let coordinator = clock.coordinator();
    let url = "https://issuer.example/keys?a=1&b=2";
    let slot = coordinator.slot(url, 1)?;
    clock.advance(60_000);
    assert!(coordinator
        .slot("https://issuer.example/keys?b=2&a=1", 1)
        .is_err());
    let same = coordinator.slot(url, 1)?;
    assert!(Arc::ptr_eq(&slot, &same));
    drop(same);
    {
        let mut guard = slot.try_lock()?;
        *guard = Some(coordinator.now());
    }
    drop(slot);
    assert!(coordinator.slot("https://issuer.example/keys", 1).is_err());
    clock.advance(29_999);
    assert!(coordinator.slot("https://issuer.example/keys", 1).is_err());
    clock.advance(1);
    assert!(coordinator.slot("https://issuer.example/keys", 1).is_ok());
    Ok(())
}

#[tokio::test]
async fn upstream_jwks_refresh_known_unusable_and_empty_kids_do_not_force_fetch() -> TestResult {
    let server = HttpFixture::new(keyset("new")).await?;
    let clock = ManualClock::new();
    let h = Harness::new(&clock, 1, 60);
    let mut value = serde_json::from_str::<Value>(&keyset("known"))?;
    value["keys"][0]["use"] = json!("enc");
    value["keys"][0]["alg"] = json!("PS256");
    h.cache
        .try_insert(&server.url, JwkSet::from_value(value)?)?;
    for kid in [None, Some(""), Some("known")] {
        assert!(h.get(&server.url, kid).await.is_ok());
        assert_eq!(server.hits(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn upstream_jwks_refresh_waiter_shares_fetch_that_outlasts_cooldown() -> TestResult {
    let server = HttpFixture::new(keyset("published")).await?;
    server.state.hold.store(true, Ordering::SeqCst);
    let clock = ManualClock::new();
    let h = Harness::new(&clock, 1, 60);
    let first = h.spawn(server.url.clone(), "first-unknown".into());
    server.wait_hits(1).await?;
    clock.advance(1000);
    let mut waiter = Box::pin(h.get(&server.url, Some("second-unknown")));
    // Poll the borrowed future through its contended slot acquisition; timeout does not drop it.
    assert!(tokio::time::timeout(Duration::from_millis(10), &mut waiter)
        .await
        .is_err());
    clock.advance(30_000);
    server.state.hold.store(false, Ordering::SeqCst);
    server.state.release.add_permits(1);
    assert!(first.await?.is_ok());
    assert!(waiter.await.is_ok());
    assert_eq!(server.hits(), 1);
    // A genuinely later request can use the next eligible interval.
    assert!(h.get(&server.url, Some("later-unknown")).await.is_ok());
    assert_eq!(server.hits(), 2);
    Ok(())
}

#[tokio::test]
async fn upstream_jwks_refresh_material_admission_preserves_old_set_on_cold_and_forced_errors(
) -> TestResult {
    let server = HttpFixture::new(keyset("old")).await?;
    let clock = ManualClock::new();
    let h = Harness::new(&clock, 1, 60);
    let old = h.get(&server.url, Some("old")).await?;
    for (kind, fields) in [("RSA", ["n", "e"]), ("EC", ["x", "y"])] {
        for field in fields {
            for invalid in ["", "!", "YR", "YQ==", "Y+", "Y/", "a"] {
                let mut key = if kind == "RSA" {
                    json!({"kty":"RSA","kid":"new","n":"AQAB","e":"AQAB"})
                } else {
                    json!({"kty":"EC","kid":"new","crv":"P-256","x":"AQAB","y":"AQAB"})
                };
                key[field] = json!(invalid);
                server.respond(StatusCode::OK, json!({"keys":[key]}).to_string());
                clock.advance(30_000);
                assert!(h.get(&server.url, Some("new")).await.is_err());
                assert_eq!(h.cache.try_get(&server.url)?.as_ref(), Some(&old));
            }
        }
    }
    let cold = Harness::new(&clock, 1, 60);
    assert!(cold.get(&server.url, Some("new")).await.is_err());
    assert!(cold.cache.try_get(&server.url)?.is_none());
    clock.advance(30_000);
    server.respond(StatusCode::OK, keyset("new"));
    assert!(!header(Some("new")).unfamiliar_kid(&cold.get(&server.url, Some("new")).await?));
    clock.advance(30_000);
    server.respond(
        StatusCode::OK,
        json!({"keys":[{"kty":"EC","kid":"ec","crv":"P-256","x":"AQAB","y":"AQAB"}]}).to_string(),
    );
    assert!(!header(Some("ec")).unfamiliar_kid(&cold.get(&server.url, Some("ec")).await?));
    Ok(())
}
