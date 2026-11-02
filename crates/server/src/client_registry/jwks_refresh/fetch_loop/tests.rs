use super::*;
use crate::client_registry::jwks_cache_control::ResponseTiming;
use crate::client_registry::jwks_validators::DateContext;
use reqwest::header::{DATE, EXPIRES, LAST_MODIFIED};
use std::time::{Duration, Instant, UNIX_EPOCH};

const URI: &str = "https://example.com/jwks";
const FORWARD: [&str; 3] = [
    "Wednesday, 01-Jul-76 12:00:01 GMT",
    "Wednesday, 01-Jul-76 12:00:31 GMT",
    "Wed, 01 Jul 2076 12:00:01 GMT",
];
const BACKWARD: [&str; 3] = [
    "Thursday, 01-Jul-76 12:00:01 GMT",
    "Thursday, 01-Jul-76 12:00:31 GMT",
    "Thu, 01 Jul 1976 12:00:01 GMT",
];

fn context(second: u8) -> DateContext {
    let utc = time::Date::from_calendar_date(2026, time::Month::July, 1)
        .unwrap()
        .with_hms(12, 0, second)
        .unwrap()
        .assume_utc();
    DateContext::from_system_time(
        UNIX_EPOCH + Duration::from_secs(u64::try_from(utc.unix_timestamp()).unwrap()),
    )
}

fn refresh<'a>(state: &'a JwksRuntimeState, policy: &'a JwksRuntimePolicy) -> RefreshLoop<'a> {
    RefreshLoop {
        state,
        policy,
        uri: URI,
        uri_hash: "fixture",
        start: Instant::now(),
        client: reqwest::blocking::Client::builder().build().unwrap(),
        candidate: None,
        captured_guard: None,
        original_url: url::Url::parse(URI).unwrap(),
        original_target: URI.into(),
        max_body: policy.max_body_bytes,
        retries: 0,
    }
}

fn bound(status: u16, dates: [&str; 3], date_context: DateContext) -> BoundResponse {
    let receipt = Instant::now();
    BoundResponse {
        response: http::Response::builder()
            .status(status)
            .header(DATE, dates[0])
            .header(EXPIRES, dates[1])
            .header(LAST_MODIFIED, dates[0])
            .body(if status == 304 {
                String::new()
            } else {
                let (mut key, _) =
                    crate::test_utils::jwk_usage::material(jsonwebtoken::Algorithm::RS256);
                key["kid"] = serde_json::json!("A");
                serde_json::json!({"keys":[key]}).to_string()
            })
            .unwrap()
            .into(),
        target: URI.into(),
        timing: ResponseTiming {
            request: receipt - Duration::from_secs(1),
            receipt,
            date_context,
        },
        follows: 0,
    }
}

fn saved(state: &JwksRuntimeState) -> CacheEntry {
    state.inner.cache.lock().unwrap().get(URI).unwrap().clone()
}

fn assert_received_dates(entry: &CacheEntry, canonical: &str, is_future: bool) {
    let (_, date) = entry.validators.conditional_headers().unwrap();
    assert_eq!(date.unwrap().as_bytes(), canonical.as_bytes());
    assert_eq!(entry.freshness.lifetime, Some(30_000_000_000));
    if is_future {
        // A future Date has zero apparent age; the one-second exchange still counts.
        assert_eq!(entry.freshness.initial_age, Some(1_000_000_000));
        assert!(entry.freshness.reusable(entry.freshness.receipt));
    } else {
        assert!(entry.freshness.initial_age.unwrap() > 1_000_000_000);
        assert!(!entry.freshness.reusable(entry.freshness.receipt));
    }
}

#[test]
fn admitted_response_uses_receipt_clock_at_rolling_year_boundary() {
    // Controlled receipt operands, without changing the host clock. A request
    // or earlier hop's clock selects the other century in each case.
    for (earlier, receipt, dates, future) in [(0, 31, FORWARD, true), (31, 0, BACKWARD, false)] {
        let state = JwksRuntimeState::default();
        let policy = JwksRuntimePolicy::default();
        let response = bound(200, dates, context(receipt));
        assert!(
            JwksValidators::from_headers(response.response.headers(), context(earlier))
                .conditional_headers()
                .is_none()
        );
        assert!(matches!(
            refresh(&state, &policy).admit_response(response, reqwest::StatusCode::OK),
            Some(JwksRefreshOutcome::AdmittedBody(_))
        ));
        assert_received_dates(&saved(&state), dates[2], future);
    }
}

#[test]
fn revalidated_response_uses_its_own_receipt_clock_for_all_dates() {
    for (earlier, receipt, dates, future) in [(0, 31, FORWARD, true), (31, 0, BACKWARD, false)] {
        let state = JwksRuntimeState::default();
        let policy = JwksRuntimePolicy::default();
        let full_dates = [dates[2], dates[2], dates[2]];
        assert!(refresh(&state, &policy)
            .admit_response(
                bound(200, full_dates, context(earlier)),
                reqwest::StatusCode::OK
            )
            .is_some());
        let entry = saved(&state);
        let response = bound(304, dates, context(receipt));
        // The old acquisition context cannot identify this returned validator.
        assert!(
            !JwksValidators::from_headers(response.response.headers(), context(earlier))
                .identifies(&entry.validators)
        );
        let validators = response.validators();
        assert!(validators.identifies(&entry.validators));
        assert!(matches!(
            refresh(&state, &policy).revalidate_body(entry, validators, response),
            Some(JwksRefreshOutcome::RevalidatedBody(_))
        ));
        assert_received_dates(&saved(&state), dates[2], future);
    }
}

#[test]
fn unavailable_receipt_clock_does_not_grant_freshness_or_short_year_validator() {
    let state = JwksRuntimeState::default();
    let policy = JwksRuntimePolicy::default();
    let unavailable =
        DateContext::from_system_time(UNIX_EPOCH + Duration::from_secs(253_402_300_800));
    let response = bound(200, FORWARD, unavailable);
    assert!(refresh(&state, &policy)
        .admit_response(response, reqwest::StatusCode::OK)
        .is_some());
    let entry = saved(&state);
    assert!(entry.validators.conditional_headers().is_none());
    assert!(entry.freshness.initial_age.is_none());
    assert!(entry.freshness.lifetime.is_none());
    assert!(!entry.freshness.reusable(entry.freshness.receipt));
}
