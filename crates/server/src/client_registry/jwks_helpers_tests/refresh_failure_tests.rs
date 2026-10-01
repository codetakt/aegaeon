use super::https_fixture::*;
use super::*;

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn expired_body_is_not_returned_after_refresh_failure() {
    let _env = env_lock().unwrap();
    let fixture = Fixture::new(vec![Step::ok("A"), Step::new(503, vec![])], false);
    let state = new_state();
    let mut policy = fixture.policy();
    policy.refresh_skew_secs = 0;
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    let result = fetch_jwks_with_state(&state, &policy, ORIGINAL);
    let requests = fixture.finish().len();
    drop(_env);
    assert!(result.is_none());
    assert_eq!(requests, 2);
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn no_cache_body_requires_successful_revalidation() {
    let _env = env_lock().unwrap();
    let fixture = Fixture::new(
        vec![
            Step::new(200, body("A")).header("Cache-Control", "no-cache, max-age=60"),
            Step::new(503, vec![]),
        ],
        false,
    );
    let state = new_state();
    let mut policy = fixture.policy();
    policy.refresh_skew_secs = 0;
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    let result = fetch_jwks_with_state(&state, &policy, ORIGINAL);
    let requests = fixture.finish().len();
    drop(_env);
    assert!(result.is_none());
    assert_eq!(requests, 2);
}
