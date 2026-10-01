use super::https_fixture::*;
use super::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn actual_https_direct_and_safe_redirect() {
    let _env = env_lock().unwrap();
    for steps in [
        vec![Step::ok("A")],
        vec![Step::redirect(OTHER), Step::ok("A")],
    ] {
        let expected = steps.len();
        let fixture = Fixture::new(steps, false);
        let policy = fixture.policy();
        assert_eq!(
            kid(fetch_jwks_with_state(&new_state(), &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        let observations = fixture.finish();
        assert_eq!(observations.len(), expected);
        assert_eq!(
            observations[0].header("accept").as_deref(),
            Some(b"*/*".as_slice())
        );
        assert!(observations[0].header("accept-encoding").is_none());
        assert!(observations[0].header("referer").is_none());
        if expected == 2 {
            assert!(observations[1].text().starts_with("GET /next HTTP/1.1\r\n"));
            assert!(observations[1].header("referer").is_none());
        }
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn redirect_hops_never_disclose_source_queries_in_headers() {
    let _env = env_lock().unwrap();
    let original = "https://1.1.1.1/jwks?token=registered-query-secret";
    for intermediate in [
        "https://1.1.1.1/intermediate?token=redirect-query-secret",
        "https://8.8.8.8/intermediate?token=redirect-query-secret",
    ] {
        for destination in ["https://1.1.1.1/final", "https://8.8.8.8/final"] {
            let fixture = Fixture::new(
                vec![
                    Step::redirect(intermediate),
                    Step::redirect(destination),
                    Step::ok("A"),
                ],
                false,
            );
            assert_eq!(
                kid(fetch_jwks_with_state(
                    &new_state(),
                    &fixture.policy(),
                    original
                ))
                .as_deref(),
                Some("A")
            );
            let observations = fixture.finish();
            assert_eq!(observations.len(), 3);
            assert!(observations[0]
                .text()
                .starts_with("GET /jwks?token=registered-query-secret HTTP/1.1\r\n"));
            assert!(observations[1]
                .text()
                .starts_with("GET /intermediate?token=redirect-query-secret HTTP/1.1\r\n"));
            assert!(observations[2]
                .text()
                .starts_with("GET /final HTTP/1.1\r\n"));
            for observation in observations {
                assert!(observation.header("referer").is_none());
                let request = observation.text();
                let (_, headers) = request.split_once("\r\n").unwrap();
                assert!(!headers.contains("registered-query-secret"));
                assert!(!headers.contains("redirect-query-secret"));
            }
        }
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn actual_tls_absent_untrusted_and_wrong_san_are_rejected() {
    let _env = env_lock().unwrap();
    for mode in 0..3 {
        let fixture = Fixture::new(vec![Step::ok("A")], mode == 2);
        let mut policy = fixture.policy();
        if mode == 0 {
            policy.ca_bundle = None;
        }
        let unrelated_ca = if mode == 1 {
            let cert =
                rcgen::Certificate::from_params(rcgen::CertificateParams::new(vec![])).unwrap();
            let path =
                std::env::temp_dir().join(format!("aegaeon-untrusted-ca-{}.pem", Uuid::new_v4()));
            std::fs::write(&path, cert.serialize_pem().unwrap()).unwrap();
            policy.ca_bundle = Some(path.clone());
            Some(path)
        } else {
            None
        };
        let state = new_state();
        assert!(fetch_jwks_with_state(&state, &policy, ORIGINAL).is_none());
        assert!(state.inner.cache.lock().unwrap().is_empty());
        let observations = fixture.finish();
        assert_eq!(observations.len(), 1);
        assert!(observations[0].request.is_empty());
        assert!(observations[0].error.is_some());
        if let Some(path) = unrelated_ca {
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn actual_redirect_guards_reject_unsafe_targets_without_connect() {
    let _env = env_lock().unwrap();
    for location in [
        "http://8.8.8.8/next",
        "https://127.0.0.1/next",
        "https://10.0.0.1/next",
        "https://192.0.2.1/next",
        "https://user@8.8.8.8/next",
    ] {
        let fixture = Fixture::new(vec![Step::redirect(location)], false);
        let policy = fixture.policy();
        let state = new_state();
        assert!(fetch_jwks_with_state(&state, &policy, ORIGINAL).is_none());
        let observations = fixture.finish();
        assert_eq!(observations.len(), 1);
        assert!(observations[0].text().starts_with("GET /jwks "));
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn normal_matching_304_returns_owned_body_and_max_age_zero_reacquires() {
    let _env = env_lock().unwrap();
    let fixture = Fixture::new(
        vec![
            Step::ok("A").header("ETag", "\"A\""),
            Step::not_modified("\"A\""),
            Step::ok("B"),
        ],
        false,
    );
    let state = new_state();
    let policy = fixture.policy();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("B")
    );
    let observations = fixture.finish();
    assert_eq!(observations.len(), 3);
    assert_eq!(
        observations[1].header("if-none-match").as_deref(),
        Some(b"\"A\"".as_slice())
    );
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn normal_date_only_obsolete_date_is_canonicalized_and_revalidated() {
    let _env = env_lock().unwrap();
    let fixture = Fixture::new(
        vec![
            Step::ok("A").header("Last-Modified", "Sunday, 06-Nov-94 08:49:37 GMT"),
            Step::new(304, vec![]).header("Last-Modified", "Sun, 06 Nov 1994 08:49:37 GMT"),
        ],
        false,
    );
    let state = new_state();
    let policy = fixture.policy();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    let observations = fixture.finish();
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[1].header("if-modified-since").as_deref(),
        Some(b"Sun, 06 Nov 1994 08:49:37 GMT".as_slice())
    );
    assert!(observations[1].header("if-none-match").is_none());
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn strict_304_tag_date_and_invalid_metadata_matrix() {
    let _env = env_lock().unwrap();
    let date = "Sun, 06 Nov 1994 08:49:37 GMT";
    let cases = vec![
        ("\"A\"", Step::not_modified("\"A\""), true),
        ("\"A\"", Step::not_modified("W/\"A\""), true),
        ("W/\"A\"", Step::not_modified("W/\"A\""), true),
        ("W/\"A\"", Step::not_modified("\"A\""), false),
        ("\"A\"", Step::not_modified("\"B\""), false),
        ("\"A\"", Step::new(304, vec![]), false),
        (
            "\"A\"",
            Step::new(304, vec![]).header("Last-Modified", date),
            true,
        ),
        (
            "\"A\"",
            Step::not_modified("\"B\"").header("Last-Modified", date),
            false,
        ),
        (
            "\"A\"",
            Step::not_modified("\"A\"").header("Last-Modified", "invalid"),
            false,
        ),
        (
            "\"A\"",
            Step::not_modified("\"A\"").header("ETag", "\"A\""),
            false,
        ),
        ("\"A\"", Step::not_modified("bad"), false),
        (
            "\"A\"",
            Step::not_modified("\"A\"").header("Last-Modified", "Mon, 07 Nov 1994 08:49:37 GMT"),
            true,
        ),
    ];
    for (tag, response, accepted) in cases {
        let mut steps = vec![
            Step::ok("A")
                .header("ETag", tag)
                .header("Last-Modified", date),
            response,
        ];
        if !accepted {
            steps.push(Step::ok("B"));
        }
        let fixture = Fixture::new(steps, false);
        let policy = fixture.policy();
        let state = new_state();
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        let result = kid(fetch_jwks_with_state(&state, &policy, ORIGINAL));
        let observations = fixture.finish();
        assert_eq!(result.as_deref(), Some(if accepted { "A" } else { "B" }));
        assert_eq!(observations.len(), if accepted { 2 } else { 3 });
        assert_eq!(
            observations[1].header("if-none-match").as_deref(),
            Some(tag.as_bytes())
        );
        if !accepted {
            assert!(observations[2].header("if-none-match").is_none());
            assert!(observations[2].header("if-modified-since").is_none());
        }
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn raw_obstext_entity_tag_roundtrips_without_utf8_loss() {
    let _env = env_lock().unwrap();
    let tag = b"\"\x80\xff\"";
    let fixture = Fixture::new(
        vec![
            Step::ok("A").header("ETag", tag),
            Step::new(304, vec![]).header("ETag", tag),
        ],
        false,
    );
    let state = new_state();
    let policy = fixture.policy();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    let result = kid(fetch_jwks_with_state(&state, &policy, ORIGINAL));
    let observations = fixture.finish();
    assert_eq!(result.as_deref(), Some("A"));
    assert_eq!(
        observations[1].header("if-none-match").as_deref(),
        Some(tag.as_slice())
    );
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn unusable_304_recovers_once_then_terminates_without_freshening() {
    let _env = env_lock().unwrap();
    let fixture = Fixture::new(
        vec![
            Step::ok("A").header("ETag", "\"A\""),
            Step::new(304, vec![]),
            Step::new(304, vec![]),
        ],
        false,
    );
    let state = new_state();
    let policy = fixture.policy();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    let original_deadline = state
        .inner
        .cache
        .lock()
        .unwrap()
        .get(ORIGINAL)
        .unwrap()
        .freshness
        .receipt;
    let result = fetch_jwks_with_state(&state, &policy, ORIGINAL);
    let observations = fixture.finish();
    assert!(result.is_none());
    assert_eq!(observations.len(), 3);
    assert!(observations[2].header("if-none-match").is_none());
    assert_eq!(
        state
            .inner
            .cache
            .lock()
            .unwrap()
            .get(ORIGINAL)
            .unwrap()
            .freshness
            .receipt,
        original_deadline
    );
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn retained_candidate_survives_gc_while_normal_304_is_in_flight() {
    let _env = env_lock().unwrap();
    let state = new_state();
    let intervention = state.clone();
    let mut revalidate = Step::not_modified("\"A\"");
    revalidate.before_response = Some(Box::new(move || {
        // Versioned D6 fixture: expire representation retention, not freshness.
        intervention
            .inner
            .cache
            .lock()
            .unwrap()
            .get_mut(ORIGINAL)
            .unwrap()
            .retain_until = Instant::now();
        *intervention.inner.last_gc.lock().unwrap() = None;
        super::super::jwks_gc::maybe_run_gc_with_state(
            &intervention,
            &JwksRuntimePolicy::default(),
        );
        assert!(!intervention
            .inner
            .cache
            .lock()
            .unwrap()
            .contains_key(ORIGINAL));
    }));
    let fixture = Fixture::new(
        vec![Step::ok("A").header("ETag", "\"A\""), revalidate],
        false,
    );
    let policy = fixture.policy();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    let result = kid(fetch_jwks_with_state(&state, &policy, ORIGINAL));
    let observations = fixture.finish();
    assert_eq!(result.as_deref(), Some("A"));
    assert_eq!(observations.len(), 2);
    assert_eq!(
        state
            .inner
            .cache
            .lock()
            .unwrap()
            .get(ORIGINAL)
            .unwrap()
            .jwks
            .keys[0]
            .kid
            .as_deref(),
        Some("A")
    );
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn waiting_acquisition_pairs_with_candidate_captured_after_uri_guard() {
    let _env = env_lock().unwrap();
    let fixture = Fixture::new(
        vec![
            Step::ok("A").header("ETag", "\"A\""),
            Step::ok("B").header("ETag", "\"B\""),
            Step::not_modified("\"B\""),
        ],
        false,
    );
    let state = new_state();
    let policy = fixture.policy();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    let a = state
        .inner
        .cache
        .lock()
        .unwrap()
        .get(ORIGINAL)
        .unwrap()
        .clone();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("B")
    );
    let b = state
        .inner
        .cache
        .lock()
        .unwrap()
        .insert(ORIGINAL.to_owned(), a)
        .unwrap();
    let uri_lock = state
        .inner
        .coordination
        .fetch_locks
        .lock()
        .unwrap()
        .get(ORIGINAL)
        .unwrap()
        .clone();
    let guard = uri_lock.lock().unwrap();
    let refs = Arc::strong_count(&uri_lock);
    let thread_state = state.clone();
    let thread_policy = policy.clone();
    let waiter =
        std::thread::spawn(move || fetch_jwks_with_state(&thread_state, &thread_policy, ORIGINAL));
    let deadline = Instant::now() + Duration::from_secs(3);
    while Arc::strong_count(&uri_lock) == refs {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    // The actual fetch_lock_for_uri has acquired its Arc; its mutex is still held.
    state
        .inner
        .cache
        .lock()
        .unwrap()
        .insert(ORIGINAL.to_owned(), b);
    drop(guard);
    let result = kid(waiter.join().unwrap());
    let observations = fixture.finish();
    assert_eq!(result.as_deref(), Some("B"));
    assert_eq!(observations.len(), 3);
    assert_eq!(
        observations[2].header("if-none-match").as_deref(),
        Some(b"\"B\"".as_slice())
    );
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn prior_redirect_target_changes_do_not_transfer_validators() {
    let _env = env_lock().unwrap();
    for first in ["https://1.1.1.1/old", OTHER] {
        let fixture = Fixture::new(
            vec![
                Step::redirect(first),
                Step::ok("A").header("ETag", "\"X\""),
                Step::redirect("https://8.8.8.8/new"),
                Step::ok("B").header("ETag", "\"X\""),
            ],
            false,
        );
        let state = new_state();
        let policy = fixture.policy();
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        let result = kid(fetch_jwks_with_state(&state, &policy, ORIGINAL));
        let observations = fixture.finish();
        assert_eq!(result.as_deref(), Some("B"));
        assert_eq!(observations.len(), 4);
        assert!(observations[2].header("if-none-match").is_none());
        assert!(observations[3].header("if-none-match").is_none());
        assert!(observations[3].text().starts_with("GET /new HTTP/1.1\r\n"));
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn conditional_redirect_recovers_at_original_with_no_validator_or_referer_leak() {
    let _env = env_lock().unwrap();
    let fixture = Fixture::new(
        vec![
            Step::ok("A").header("ETag", "\"A\""),
            Step::redirect(OTHER),
            Step::redirect(OTHER).header("Set-Cookie", "secret=fixture"),
            Step::ok("B"),
        ],
        false,
    );
    let state = new_state();
    let policy = fixture.policy();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    let result = kid(fetch_jwks_with_state(&state, &policy, ORIGINAL));
    let observations = fixture.finish();
    assert_eq!(result.as_deref(), Some("B"));
    assert_eq!(observations.len(), 4);
    assert!(observations[1].text().starts_with("GET /jwks "));
    assert!(observations[2].text().starts_with("GET /jwks "));
    assert!(observations[3].text().starts_with("GET /next "));
    assert!(observations[2].header("if-none-match").is_none());
    assert!(observations[2].header("referer").is_none());
    for name in [
        "if-none-match",
        "if-modified-since",
        "cookie",
        "authorization",
        "proxy-authorization",
        "accept-encoding",
        "referer",
    ] {
        assert!(observations[3].header(name).is_none(), "leaked {name}");
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn encoded_dot_successor_uses_canonicalized_sent_target() {
    let _env = env_lock().unwrap();
    let mut response = Step::ok("B");
    response
        .path_bodies
        .push(("/dir/%2e%2e/jwks?x=1", body("A")));
    let fixture = Fixture::new(
        vec![Step::redirect("/dir/%2e%2e/jwks?x=1"), response],
        false,
    );
    let state = new_state();
    let policy = fixture.policy();
    let result = kid(fetch_jwks_with_state(&state, &policy, ORIGINAL));
    let observations = fixture.finish();
    assert_eq!(result.as_deref(), Some("B"));
    assert_eq!(observations.len(), 2);
    assert!(observations[1]
        .text()
        .starts_with("GET /jwks?x=1 HTTP/1.1\r\n"));
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn redirect_status_locations_follow_limit_cycles_and_query_fragments() {
    let _env = env_lock().unwrap();
    for status in [301, 302, 303, 307, 308] {
        let fixture = Fixture::new(
            vec![
                Step::new(status, vec![]).header("Location", OTHER),
                Step::ok("A"),
            ],
            false,
        );
        assert_eq!(
            kid(fetch_jwks_with_state(
                &new_state(),
                &fixture.policy(),
                ORIGINAL
            ))
            .as_deref(),
            Some("A")
        );
        assert_eq!(fixture.finish().len(), 2);
    }
    for step in [
        Step::new(300, vec![]).header("Location", OTHER),
        Step::new(304, vec![]),
        Step::new(305, vec![]).header("Location", OTHER),
        Step::new(306, vec![]).header("Location", OTHER),
        Step::new(302, vec![]),
        Step::redirect("not a uri"),
        Step::redirect("https://[invalid]"),
    ] {
        let fixture = Fixture::new(vec![step], false);
        assert!(fetch_jwks_with_state(&new_state(), &fixture.policy(), ORIGINAL).is_none());
        assert_eq!(fixture.finish().len(), 1);
    }
    let fixture = Fixture::new(
        vec![
            Step::redirect(OTHER).header("Location", "https://1.1.1.1/ignored"),
            Step::ok("A"),
        ],
        false,
    );
    assert_eq!(
        kid(fetch_jwks_with_state(
            &new_state(),
            &fixture.policy(),
            ORIGINAL
        ))
        .as_deref(),
        Some("A")
    );
    assert!(fixture.finish()[1].text().starts_with("GET /next "));
    let fixture = Fixture::new(
        vec![
            Step::redirect("?a=1#fragment"),
            Step::redirect("#new"),
            Step::redirect(OTHER),
        ],
        false,
    );
    assert!(fetch_jwks_with_state(&new_state(), &fixture.policy(), ORIGINAL).is_none());
    let obs = fixture.finish();
    assert_eq!(obs.len(), 3);
    assert!(obs[1].text().starts_with("GET /jwks?a=1 "));
    assert!(obs[2].text().starts_with("GET /jwks?a=1 "));
    assert!(obs
        .iter()
        .all(|observation| observation.header("referer").is_none()));
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn shared_retry_budget_does_not_reset_after_recovery_or_redirects() {
    let _env = env_lock().unwrap();
    for retries in [0, 1] {
        let mut steps = vec![Step::ok("A").header("ETag", "\"A\"")];
        if retries == 1 {
            steps.push(Step::new(503, vec![]));
        }
        steps.extend([
            Step::new(304, vec![]),
            Step::redirect(OTHER),
            Step::new(503, vec![]),
        ]);
        let expected = steps.len();
        let fixture = Fixture::new(steps, false);
        let mut policy = fixture.policy();
        policy.http_retries = retries;
        let state = new_state();
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        let result = fetch_jwks_with_state(&state, &policy, ORIGINAL);
        let obs = fixture.finish();
        assert!(result.is_none());
        assert_eq!(obs.len(), expected);
        assert!(obs[expected - 2].text().starts_with("GET /jwks "));
        assert!(obs[expected - 2].header("if-none-match").is_none());
    }
    // With a budget still available after recovery, the complete chain restarts at original.
    let fixture = Fixture::new(
        vec![
            Step::ok("A").header("ETag", "\"A\""),
            Step::new(304, vec![]),
            Step::redirect(OTHER),
            Step::new(503, vec![]),
            Step::redirect(OTHER),
            Step::ok("B"),
        ],
        false,
    );
    let mut policy = fixture.policy();
    policy.http_retries = 1;
    let state = new_state();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("B")
    );
    let obs = fixture.finish();
    assert_eq!(obs.len(), 6);
    assert!(obs[4].text().starts_with("GET /jwks "));
    assert!(obs[4].header("referer").is_none());
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn response_timeout_is_per_explicit_hop_and_body_read() {
    let _env = env_lock().unwrap();
    let mut first = Step::redirect(OTHER);
    first.header_delay = Duration::from_millis(600);
    let mut second = Step::redirect("https://1.1.1.1/final");
    second.header_delay = Duration::from_millis(600);
    let mut final_step = Step::ok("A");
    final_step.header_delay = Duration::from_millis(600);
    let fixture = Fixture::new(vec![first, second, final_step], false);
    let mut policy = fixture.policy();
    policy.http_timeout_secs = 1;
    let start = Instant::now();
    let result = kid(fetch_jwks_with_state(&new_state(), &policy, ORIGINAL));
    let elapsed = start.elapsed();
    let obs = fixture.finish();
    assert_eq!(result.as_deref(), Some("A"));
    assert_eq!(obs.len(), 3);
    assert!(elapsed > Duration::from_secs(1));
    let bytes = body("A");
    let mid = bytes.len() / 2;
    let mut response = Step::new(200, vec![]);
    response.chunks = vec![
        (Duration::from_millis(600), bytes[..mid].to_vec()),
        (Duration::from_millis(600), bytes[mid..].to_vec()),
    ];
    let fixture = Fixture::new(vec![response], false);
    let mut policy = fixture.policy();
    policy.http_timeout_secs = 1;
    assert_eq!(
        kid(fetch_jwks_with_state(&new_state(), &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    fixture.finish();
    let mut slow = Step::ok("A");
    slow.header_delay = Duration::from_millis(1300);
    let fixture = Fixture::new(vec![slow], false);
    let mut policy = fixture.policy();
    policy.http_timeout_secs = 1;
    assert!(fetch_jwks_with_state(&new_state(), &policy, ORIGINAL).is_none());
    assert_eq!(fixture.finish().len(), 1);
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn one_client_keeps_captured_ca_and_proxy_across_recovery() {
    let _env = env_lock().unwrap();
    let fixture = Fixture::new(vec![Step::ok("A").header("ETag", "\"A\"")], false);
    let state = new_state();
    let policy = fixture.policy();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    fixture.finish();
    let mut response = Step::new(304, vec![]);
    let path = Arc::new(std::sync::Mutex::new(None::<std::path::PathBuf>));
    let callback_path = path.clone();
    response.before_response = Some(Box::new(move || {
        std::fs::remove_file(callback_path.lock().unwrap().as_ref().unwrap()).unwrap();
        for key in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            std::env::set_var(key, "http://127.0.0.1:1");
        }
    }));
    let fixture = Fixture::new(vec![response, Step::redirect(OTHER), Step::ok("B")], false);
    *path.lock().unwrap() = Some(fixture.ca_path.clone());
    let policy = fixture.policy();
    let result = kid(fetch_jwks_with_state(&state, &policy, ORIGINAL));
    let obs = fixture.finish();
    assert_eq!(result.as_deref(), Some("B"));
    assert_eq!(obs.len(), 3);
    assert!(obs[0].header("if-none-match").is_some());
    assert!(obs[1].header("if-none-match").is_none());
    assert!(obs[2].text().starts_with("GET /next "));
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn ordinary_errors_at_each_hop_restart_original_and_share_budget() {
    let _env = env_lock().unwrap();
    for status in [0, 503] {
        for failing_hop in 1..=3 {
            let mut steps = vec![];
            for hop in 1..failing_hop {
                steps.push(Step::redirect(if hop == 1 {
                    OTHER
                } else {
                    "https://1.1.1.1/final"
                }));
            }
            steps.push(Step::new(status, vec![]));
            steps.extend([
                Step::redirect(OTHER),
                Step::redirect("https://1.1.1.1/final"),
                Step::ok("A"),
            ]);
            let fixture = Fixture::new(steps, false);
            let mut policy = fixture.policy();
            policy.http_retries = 1;
            let result = kid(fetch_jwks_with_state(&new_state(), &policy, ORIGINAL));
            let obs = fixture.finish();
            assert_eq!(result.as_deref(), Some("A"));
            assert_eq!(obs.len(), failing_hop + 3);
            assert!(obs[failing_hop].text().starts_with("GET /jwks "));
            assert!(obs[failing_hop].header("referer").is_none());
        }
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn timed_out_conditional_redirect_never_gains_follow_permission() {
    let _env = env_lock().unwrap();
    let mut late = Step::redirect(OTHER);
    late.header_delay = Duration::from_millis(1300);
    let fixture = Fixture::new(
        vec![
            Step::ok("A").header("ETag", "\"A\""),
            late,
            Step::not_modified("\"A\""),
        ],
        false,
    );
    let policy = fixture.policy();
    let state = new_state();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    let mut policy = policy;
    policy.http_retries = 1;
    policy.http_timeout_secs = 1;
    let result = kid(fetch_jwks_with_state(&state, &policy, ORIGINAL));
    let obs = fixture.finish();
    assert_eq!(result.as_deref(), Some("A"));
    assert_eq!(obs.len(), 3);
    for request in &obs {
        assert!(request.text().starts_with("GET /jwks "));
        assert!(request.connect.starts_with("CONNECT 1.1.1.1:443 "));
    }
    assert_eq!(
        obs[2].header("if-none-match").as_deref(),
        Some(b"\"A\"".as_slice())
    );
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn matching_304_inherits_lifetime_and_restarts_exchange_age() {
    let _env = env_lock().unwrap();
    let fixture = Fixture::new(
        vec![
            Step::ok("A").header("ETag", "\"A\""),
            Step::new(304, vec![]).header("ETag", "\"A\""),
            Step::ok("B"),
        ],
        false,
    );
    let state = new_state();
    let policy = fixture.policy();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    let expiry = state
        .inner
        .cache
        .lock()
        .unwrap()
        .get(ORIGINAL)
        .unwrap()
        .freshness
        .receipt;
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    assert_ne!(
        state
            .inner
            .cache
            .lock()
            .unwrap()
            .get(ORIGINAL)
            .unwrap()
            .freshness
            .receipt,
        expiry
    );
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("B")
    );
    assert_eq!(fixture.finish().len(), 3);
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn body_read_timeout_rejects_body_without_retry_or_admission() {
    let _env = env_lock().unwrap();
    let mut response = Step::new(200, vec![]);
    response.chunks = vec![(Duration::from_millis(1300), body("A"))];
    let fixture = Fixture::new(vec![response], false);
    let mut policy = fixture.policy();
    policy.http_timeout_secs = 1;
    policy.http_retries = 1;
    let state = new_state();
    assert!(fetch_jwks_with_state(&state, &policy, ORIGINAL).is_none());
    assert!(state.inner.cache.lock().unwrap().is_empty());
    assert_eq!(fixture.finish().len(), 1);
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn failed_refresh_uses_only_current_fresh_replacement() {
    let _env = env_lock().unwrap();
    for expires_during in [true, false] {
        let state = new_state();
        let next = Arc::new(std::sync::Mutex::new(None));
        let callback_next = next.clone();
        let callback_state = state.clone();
        let mut failure = Step::new(503, vec![]);
        failure.header_delay = Duration::from_millis(120);
        failure.before_response = Some(Box::new(move || {
            let mut replacement: CacheEntry = callback_next.lock().unwrap().take().unwrap();
            fixture_fresh_for(
                &mut replacement,
                if expires_during {
                    Duration::from_millis(50)
                } else {
                    Duration::from_secs(60)
                },
            );
            callback_state
                .inner
                .cache
                .lock()
                .unwrap()
                .insert(ORIGINAL.to_owned(), replacement);
        }));
        let fixture = Fixture::new(
            vec![
                Step::ok("A").header("ETag", "\"A\""),
                Step::ok("B").header("ETag", "\"B\""),
                failure,
            ],
            false,
        );
        let policy = fixture.policy();
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        let a = state
            .inner
            .cache
            .lock()
            .unwrap()
            .get(ORIGINAL)
            .unwrap()
            .clone();
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("B")
        );
        *next.lock().unwrap() = state
            .inner
            .cache
            .lock()
            .unwrap()
            .insert(ORIGINAL.to_owned(), a);
        let result = kid(fetch_jwks_with_state(&state, &policy, ORIGINAL));
        let obs = fixture.finish();
        assert_eq!(
            result.as_deref(),
            if expires_during { None } else { Some("B") }
        );
        assert_eq!(obs.len(), 3);
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn fresh_hit_does_not_wait_for_background_guard_and_background_captures_current_pair() {
    let _env = env_lock().unwrap();
    let fixture = Fixture::new(
        vec![
            Step::ok("A").header("ETag", "\"A\""),
            Step::ok("B").header("ETag", "\"B\""),
            Step::not_modified("\"B\""),
        ],
        false,
    );
    let state = new_state();
    let mut policy = fixture.policy();
    policy.refresh_skew_secs = 120;
    policy.local_cache_max_entries = 1;
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    let mut a = state
        .inner
        .cache
        .lock()
        .unwrap()
        .get(ORIGINAL)
        .unwrap()
        .clone();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("B")
    );
    fixture_fresh_for(&mut a, Duration::from_secs(60));
    let b = state
        .inner
        .cache
        .lock()
        .unwrap()
        .insert(ORIGINAL.to_owned(), a)
        .unwrap();
    let lock = state
        .inner
        .coordination
        .fetch_locks
        .lock()
        .unwrap()
        .get(ORIGINAL)
        .unwrap()
        .clone();
    let guard = lock.lock().unwrap();
    let count = Arc::strong_count(&lock);
    let fetch_state = state.clone();
    let fetch_policy = policy.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let foreground = std::thread::spawn(move || {
        send.send(kid(fetch_jwks_with_state(
            &fetch_state,
            &fetch_policy,
            ORIGINAL,
        )))
        .unwrap()
    });
    assert_eq!(
        receive
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .as_deref(),
        Some("A")
    );
    foreground.join().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Arc::strong_count(&lock) == count {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(state
        .inner
        .coordination
        .fetch_lock(1, OTHER)
        .unwrap()
        .is_none());
    assert!(Arc::ptr_eq(
        &lock,
        &state
            .inner
            .coordination
            .fetch_lock(1, ORIGINAL)
            .unwrap()
            .unwrap()
    ));
    state
        .inner
        .cache
        .lock()
        .unwrap()
        .insert(ORIGINAL.to_owned(), b);
    drop(guard);
    while state
        .inner
        .coordination
        .background_refreshes
        .lock()
        .unwrap()
        .contains(ORIGINAL)
    {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let obs = fixture.finish();
    assert_eq!(obs.len(), 3);
    assert_eq!(
        obs[2].header("if-none-match").as_deref(),
        Some(b"\"B\"".as_slice())
    );
    assert_eq!(
        state
            .inner
            .cache
            .lock()
            .unwrap()
            .get(ORIGINAL)
            .unwrap()
            .jwks
            .keys[0]
            .kid
            .as_deref(),
        Some("B")
    );
    assert_eq!(state.inner.cache.lock().unwrap().len(), 1);
}
