use super::*;

#[test]
fn auth_session_store_expires_and_evicts_sessions() -> TokenExchangeTestResult {
    let store = AuthSessionStore::new_process_local_with_limits_for_tests(3600, 1);
    let now = must_ok!(now_epoch_secs(), "test clock should be valid");
    let first = must_some!(
        store.create("user-A", AuthSessionTimes::local(now), None, None, None),
        "session created",
    );
    assert!(must_ok!(
        store.try_get(&first),
        "in-memory auth session store should confirm lookup",
    )
    .is_some());

    let second = must_some!(
        store.create(
            "user-B",
            AuthSessionTimes::local(now.saturating_add(1)),
            None,
            None,
            None,
        ),
        "session created",
    );
    assert!(must_ok!(
        store.try_get(&first),
        "in-memory auth session store should confirm lookup",
    )
    .is_none());
    assert!(must_ok!(
        store.try_get(&second),
        "in-memory auth session store should confirm lookup",
    )
    .is_some());

    let expired = must_some!(
        store.create(
            "user-C",
            AuthSessionTimes::local(now.saturating_sub(7200)),
            None,
            None,
            None,
        ),
        "session created",
    );
    assert!(must_ok!(
        store.try_get(&expired),
        "in-memory auth session store should confirm lookup",
    )
    .is_none());
    Ok(())
}

#[test]
fn auth_session_store_keeps_created_session_when_capacity_timestamps_tie() -> TokenExchangeTestResult
{
    let store = AuthSessionStore::new_process_local_with_limits_for_tests(3600, 1);
    let now = must_ok!(now_epoch_secs(), "test clock should be valid");
    let first = must_some!(
        store.create("user-A", AuthSessionTimes::local(now), None, None, None),
        "session created",
    );
    let second = must_some!(
        store.create("user-B", AuthSessionTimes::local(now), None, None, None),
        "session created",
    );

    assert!(must_ok!(
        store.try_get(&first),
        "in-memory auth session store should confirm lookup",
    )
    .is_none());
    assert!(
        must_ok!(
            store.try_get(&second),
            "in-memory auth session store should confirm lookup",
        )
        .is_some(),
        "create must not return a sid evicted by same-timestamp capacity enforcement"
    );
    Ok(())
}

#[test]
fn auth_session_uses_creation_time_for_ttl_and_upstream_time_for_auth_age(
) -> TokenExchangeTestResult {
    let store = AuthSessionStore::new_process_local_with_limits_for_tests(3600, 10);
    let created_at = must_ok!(now_epoch_secs(), "test clock should be valid");
    let upstream_auth_time = created_at.saturating_sub(7200);
    let sid = must_some!(
        store.create(
            "user-A",
            must_some!(
                AuthSessionTimes::from_upstream(created_at, upstream_auth_time.cast_signed()),
                "past upstream auth_time should be accepted",
            ),
            None,
            None,
            None,
        ),
        "session created",
    );
    let session = must_some!(
        must_ok!(
            store.try_get(&sid),
            "in-memory auth session store should confirm lookup",
        ),
        "fresh session should be live",
    );

    assert_eq!(session.created_at_epoch_secs, created_at);
    assert_eq!(session.auth_time_epoch_secs, upstream_auth_time);
    assert_eq!(
        session.expires_at_epoch_secs,
        created_at.saturating_add(3600)
    );
    Ok(())
}

#[test]
fn auth_session_ttl_is_bounded() {
    let store = AuthSessionStore::new_process_local_with_limits_for_tests(u64::MAX, 10);

    assert_eq!(store.cookie_ttl_secs(), MAX_AUTH_SESSION_TTL_SECS);
}

#[test]
fn auth_session_create_rejects_unrepresentable_expiry() {
    let store = AuthSessionStore::new_process_local_with_limits_for_tests(3600, 10);

    assert!(store
        .create(
            "user-A",
            AuthSessionTimes::local(u64::MAX),
            None,
            None,
            None,
        )
        .is_none());
}

#[test]
fn auth_session_rejects_future_upstream_auth_time() -> TokenExchangeTestResult {
    let created_at = must_ok!(now_epoch_secs(), "test clock should be valid");
    let times =
        AuthSessionTimes::from_upstream(created_at, created_at.saturating_add(7200).cast_signed());

    assert!(times.is_none());
    Ok(())
}

#[test]
fn auth_session_rejects_negative_upstream_auth_time() -> TokenExchangeTestResult {
    let created_at = must_ok!(now_epoch_secs(), "test clock should be valid");

    assert!(AuthSessionTimes::from_upstream(created_at, -1).is_none());
    Ok(())
}

#[test]
fn auth_session_cookie_has_bounded_lifetime() {
    let cookie = build_session_set_cookie("sid-1", 42);
    assert!(cookie.contains("Max-Age=42"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("Secure"));
}
