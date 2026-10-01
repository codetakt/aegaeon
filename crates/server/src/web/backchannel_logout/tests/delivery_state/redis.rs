use super::*;
use ::redis::Commands;

fn connection(f: &SessionFixture) -> TestResult<(::redis::Connection, String, String)> {
    let (url, prefix) = f
        .redis
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Redis fixture"))?;
    Ok((
        ::redis::Client::open(url.as_str())?.get_connection()?,
        format!("{prefix}:session:{}", f.event.sid),
        format!("{prefix}:clients:{}", f.event.sid),
    ))
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_concurrent_canonical_claims() -> TestResult {
    let f = SessionFixture::redis(600)?;
    let mut first = f.claim("a", "first", NOW, Some(f.candidate("a", NOW)?));
    let mut second = f.claim("a", "second", NOW, Some(f.candidate("a", NOW)?));
    let barrier = Arc::new(std::sync::Barrier::new(2));
    first.before_cas = Some(barrier.clone());
    second.before_cas = Some(barrier);
    let (one, two) = std::thread::scope(|scope| {
        let one = scope.spawn(|| f.a.delivery_transition(&first));
        let two = scope.spawn(|| f.b.delivery_transition(&second));
        (
            one.join().expect("claim worker"),
            two.join().expect("claim worker"),
        )
    });
    let outcomes = [
        one.map_err(anyhow::Error::msg)?,
        two.map_err(anyhow::Error::msg)?,
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, Outcome::Granted(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, Outcome::Deferred))
            .count(),
        1
    );
    let (mut conn, key, _) = connection(&f)?;
    let record: String = conn.hget(&key, crate::oidc::session::delivery::recipient_field("a"))?;
    let stored: serde_json::Value = serde_json::from_str(&record)?;
    for outcome in outcomes {
        if let Outcome::Granted(p) = outcome {
            assert!(stored["candidate"]["token"] == p.token);
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_legacy_corrupt_missing_and_membership() -> TestResult {
    let f = SessionFixture::redis(600)?;
    let (mut conn, key, clients) = connection(&f)?;
    let before: u64 = conn.hlen(&key)?;
    assert!(f.apply(&f.request("unknown", Command::Probe, NOW)).is_err());
    assert_eq!(conn.hlen::<_, u64>(&key)?, before);
    conn.hdel::<_, _, ()>(&key, "logout_delivery_version")?;
    assert!(matches!(
        f.apply(&f.request("a", Command::Probe, NOW))?,
        Outcome::LegacyUnknown
    ));
    assert!(f
        .a
        .try_logout_by_sid_at(&f.event.sid, NOW)
        .map_err(anyhow::Error::msg)?
        .is_some());
    assert!(!conn.hexists::<_, _, bool>(&key, "logout_delivery_version")?);
    conn.hset::<_, _, _, ()>(&key, "logout_delivery_version", "1")?;
    let field = crate::oidc::session::delivery::recipient_field("a");
    for corrupt in ["", "{}", "null", "not-json"] {
        conn.hset::<_, _, _, ()>(&key, &field, corrupt)?;
        assert!(f.apply(&f.request("a", Command::Probe, NOW)).is_err());
    }
    conn.hdel::<_, _, ()>(&key, &field)?;
    conn.set::<_, _, ()>(&clients, "wrong-type")?;
    assert!(f.apply(&f.request("a", Command::Probe, NOW)).is_err());
    conn.del::<_, ()>(&key)?;
    assert!(matches!(
        f.apply(&f.request("a", Command::Probe, NOW))?,
        Outcome::Missing
    ));
    assert!(!conn.exists::<_, bool>(&key)?);
    conn.del::<_, ()>(&clients)?;
    Ok(())
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_retention_never_extends_and_cleanup_removes_state() -> TestResult {
    let f = SessionFixture::redis(30)?;
    let (mut conn, key, clients) = connection(&f)?;
    let initial: i64 = conn.pttl(&key)?;
    let p = permit(f.apply(&f.claim("a", "owner", NOW, Some(f.candidate("a", NOW)?)))?)?;
    f.apply(&f.request(
        "a",
        Command::Complete(p, Completion::Recoverable { retry_after: None }),
        NOW,
    ))?;
    let retry = permit(f.apply(&f.claim("a", "owner2", NOW + 5, None))?)?;
    assert_eq!(retry.horizon, NOW + 30);
    let final_ttl: i64 = conn.pttl(&key)?;
    assert!(final_ttl > 0 && final_ttl <= initial);
    assert!(matches!(
        f.apply(&f.request("a", Command::Probe, NOW + 30))?,
        Outcome::Terminal
    ));
    f.a.prune_expired_at(NOW + 30);
    assert!(!conn.exists::<_, bool>(&key)?);
    assert!(!conn.exists::<_, bool>(&clients)?);
    assert!(matches!(
        f.apply(&f.request("a", Command::Probe, NOW + 31))?,
        Outcome::Missing
    ));
    Ok(())
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_sid_and_user_writers_and_full_integer_precision() -> TestResult {
    let mut f = SessionFixture::redis(600)?;
    let sid = f.a.get_or_create_session("subject", "new-browser");
    f.a.add_client(&sid, "a");
    let now = 9_007_199_254_740_993;
    f.event =
        f.a.try_logout_by_sid_at(&sid, now)
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("event"))?;
    let (mut conn, key, _) = connection(&f)?;
    assert_eq!(
        conn.hget::<_, _, String>(&key, "logged_out_at_epoch_secs")?,
        now.to_string()
    );
    assert_eq!(
        conn.hget::<_, _, String>(&key, "logout_delivery_deadline")?,
        (now + 600).to_string()
    );
    let p = permit(f.apply(&f.claim("a", "owner", now, Some(f.candidate("a", now)?)))?)?;
    f.apply(&f.request(
        "a",
        Command::Complete(p, Completion::Recoverable { retry_after: None }),
        now,
    ))?;
    assert!(matches!(
        f.apply(&f.claim("a", "early", now + 4, None))?,
        Outcome::Deferred
    ));
    assert!(matches!(
        f.apply(&f.claim("a", "due", now + 5, None))?,
        Outcome::Granted(_)
    ));
    f.a.prune_expired_at(now + 600);
    let sid = f.a.get_or_create_session("subject", "user-writer");
    f.a.add_client(&sid, "a");
    f.event =
        f.a.try_logout_by_user("subject")
            .map_err(anyhow::Error::msg)?
            .pop()
            .ok_or_else(|| anyhow::anyhow!("user event"))?;
    let (mut conn, key, _) = connection(&f)?;
    assert_eq!(
        conn.hget::<_, _, String>(&key, "logout_delivery_version")?,
        "1"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    assert!(matches!(
        f.apply(&f.request("a", Command::Probe, now))?,
        Outcome::Ready {
            needs_candidate: true
        }
    ));
    Ok(())
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_corrupt_token_and_digest_collision_identity_fail_closed() -> TestResult {
    let f = SessionFixture::redis(600)?;
    f.apply(&f.claim("a", "owner", NOW, Some(f.candidate("a", NOW)?)))?;
    let (mut conn, key, _) = connection(&f)?;
    let field = crate::oidc::session::delivery::recipient_field("a");
    let raw: String = conn.hget(&key, &field)?;
    let original: Value = serde_json::from_str(&raw)?;
    for property in ["token", "identity"] {
        let mut corrupt = original.clone();
        if property == "token" {
            corrupt["candidate"]["token"] = json!("corrupt");
        } else {
            corrupt["identity"]["client_id"] = json!("b");
        }
        conn.hset::<_, _, _, ()>(&key, &field, serde_json::to_string(&corrupt)?)?;
        assert!(f.apply(&f.request("a", Command::Probe, NOW)).is_err());
    }
    conn.hset::<_, _, _, ()>(&key, &field, raw)?;
    assert!(matches!(
        f.apply(&f.request("a", Command::Probe, NOW + 300))?,
        Outcome::Terminal
    ));
    Ok(())
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_real_fractional_clock_preserves_retry_delay() -> TestResult {
    let mut f = SessionFixture::redis(600)?;
    f.a.prune_expired_at(NOW + 600);
    let (mut conn, _, _) = connection(&f)?;
    let initial: (u64, u64) = ::redis::cmd("TIME").query(&mut conn)?;
    let sid = f.a.get_or_create_session("subject", "real-clock");
    f.a.add_client(&sid, "a");
    f.event =
        f.a.try_logout_by_sid_at(&sid, initial.0)
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("event"))?;
    let mut claim = f.claim("a", "owner", initial.0, Some(f.candidate("a", initial.0)?));
    claim.test_now = None;
    let owner = permit(f.apply(&claim)?)?;
    let before: (u64, u64) = ::redis::cmd("TIME").query(&mut conn)?;
    let mut complete = f.request(
        "a",
        Command::Complete(owner, Completion::Recoverable { retry_after: None }),
        initial.0,
    );
    complete.test_now = None;
    assert!(matches!(f.apply(&complete)?, Outcome::Deferred));
    let (_, key, _) = connection(&f)?;
    let raw: String = conn.hget(&key, crate::oidc::session::delivery::recipient_field("a"))?;
    let record: Value = serde_json::from_str(&raw)?;
    let due = record["phase"]["due"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("retry due"))?;
    let observed = record["observed_at"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("observed time"))?;
    assert!(due >= before.0 + u64::from(before.1 != 0) + 5);
    assert!((observed + 5..=observed + 6).contains(&due));
    // The common same-second case proves that Redis TIME's microseconds reach Rust.
    if observed == before.0 && before.1 != 0 {
        assert_eq!(due, observed + 6);
    }
    assert!(matches!(
        f.apply(&f.claim("a", "early", due - 1, None))?,
        Outcome::Deferred
    ));
    assert!(matches!(
        f.apply(&f.claim("a", "due", due, None))?,
        Outcome::Granted(_)
    ));
    Ok(())
}
