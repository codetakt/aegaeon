use super::*;
use crate::organizations::authentication::OriginalAuthentication;
use crate::web::auth_session::SessionAuthentication;
use uuid::Uuid;

fn evidence(now: u64) -> OriginalAuthentication {
    OriginalAuthentication::fixture(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "user-A",
        i64::try_from(now - 10).unwrap(),
        i64::try_from(now).unwrap(),
    )
}

#[test]
fn organizations_original_authentication_legacy_and_corrupt_session_fail_closed() {
    let facts = evidence(1000);
    let store = AuthSessionStore::new_process_local_for_tests();
    let sid = store
        .try_create_bound(
            "user-A",
            AuthSessionTimes::from_upstream(1000, 990).unwrap(),
            SessionAuthentication {
                original: Some(facts.clone()),
                ..Default::default()
            },
        )
        .unwrap()
        .unwrap();
    // The DTO is tested directly because this historical fixture is expired now.
    let _ = sid;
    let mut dto = RedisAuthSession {
        user_id: "user-A".into(),
        created_at_epoch_secs: 1000,
        auth_time_epoch_secs: 990,
        expires_at_epoch_secs: 2000,
        acr: None,
        claim_release_policy: None,
        upstream_logout: None,
        original_authentication: Some(facts.clone()),
    };
    assert_eq!(
        dto.to_session().unwrap().original_authentication,
        Some(facts)
    );
    dto.auth_time_epoch_secs = 1000;
    assert!(
        dto.to_session().is_none(),
        "session creation cannot refresh original authentication"
    );
    dto.auth_time_epoch_secs = 990;
    dto.user_id = "user-B".into();
    assert!(
        dto.to_session().is_none(),
        "evidence cannot move to another identity"
    );
    dto.user_id = "user-A".into();
    dto.original_authentication.as_mut().unwrap().version = 2;
    assert!(dto.to_session().is_none());
    let mut value = serde_json::to_value(&dto).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("original_authentication");
    let legacy: RedisAuthSession = serde_json::from_value(value).unwrap();
    assert!(legacy
        .to_session()
        .unwrap()
        .original_authentication
        .is_none());
    assert!(store
        .try_create_bound(
            "user-B",
            AuthSessionTimes::from_upstream(1000, 990).unwrap(),
            SessionAuthentication {
                original: Some(evidence(1000)),
                ..Default::default()
            }
        )
        .is_err());
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_organizations_original_authentication_shared_store_preserves_signed_evidence(
) -> WebAuthSessionTestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    let prefix = format!("auth-session-test:v2:{{{}}}", Uuid::new_v4());
    let a = redis_auth_session_store_for_test(&url, &prefix)?;
    let b = redis_auth_session_store_for_test(&url, &prefix)?;
    let now = now_epoch_secs()?;
    let facts = evidence(now);
    let sid = a
        .try_create_bound(
            "user-A",
            AuthSessionTimes::from_upstream(now, facts.auth_time).ok_or("time")?,
            SessionAuthentication {
                original: Some(facts.clone()),
                ..Default::default()
            },
        )?
        .ok_or("session")?;
    let restored = b.try_get(&sid)?.ok_or("shared session")?;
    assert_eq!(restored.original_authentication, Some(facts));
    assert!(b.try_delete(&sid)?);
    assert!(a.try_get(&sid)?.is_none());
    clear_redis_auth_session_store_for_test(&url, &prefix)
}
