use super::*;

fn attempts_and_identity(f: &SessionFixture) -> TestResult {
    let first = permit(f.apply(&f.claim("a", "owner-1", NOW, Some(f.candidate("a", NOW)?)))?)?;
    let losing =
        f.b.delivery_transition(&f.claim("a", "loser", NOW, Some(f.candidate("a", NOW)?)))
            .map_err(anyhow::Error::msg)?;
    assert!(matches!(losing, Outcome::Deferred));
    let other = permit(f.apply(&f.claim("b", "other", NOW, Some(f.candidate("b", NOW)?)))?)?;
    let a = verify_token(&local_key()?, &first.token, "logout+jwt")?;
    let b = verify_token(&local_key()?, &other.token, "logout+jwt")?;
    assert_ne!(a["jti"], b["jti"]);
    assert_ne!(a["jti"], f.event.jti);
    assert!(matches!(
        f.apply(&f.request("b", Command::Complete(other, Completion::Delivered), NOW))?,
        Outcome::Completed
    ));
    assert!(matches!(
        f.apply(&f.request(
            "a",
            Command::Complete(first.clone(), Completion::Recoverable { retry_after: None }),
            NOW
        ))?,
        Outcome::Deferred
    ));
    assert!(matches!(
        f.apply(&f.claim("a", "early", NOW + 4, None))?,
        Outcome::Deferred
    ));
    let second = permit(f.apply(&f.claim("a", "owner-2", NOW + 5, None))?)?;
    assert!(first.token == second.token);
    assert_eq!(second.attempt, 2);
    assert!(matches!(
        f.apply(&f.request(
            "a",
            Command::Complete(first.clone(), Completion::Delivered),
            NOW + 5
        ))?,
        Outcome::Deferred
    ));
    assert!(matches!(
        f.apply(&f.request(
            "a",
            Command::Complete(second, Completion::Recoverable { retry_after: None }),
            NOW + 5
        ))?,
        Outcome::Deferred
    ));
    assert!(matches!(
        f.apply(&f.claim("a", "early", NOW + 14, None))?,
        Outcome::Deferred
    ));
    let third = permit(f.apply(&f.claim("a", "owner-3", NOW + 15, None))?)?;
    assert_eq!(third.attempt, 3);
    assert!(matches!(
        f.apply(&f.request(
            "a",
            Command::Complete(third, Completion::Recoverable { retry_after: None }),
            NOW + 15
        ))?,
        Outcome::Terminal
    ));
    assert!(matches!(
        f.apply(&f.claim("a", "never", NOW + 100, None))?,
        Outcome::Terminal
    ));
    assert!(matches!(
        f.apply(&f.request("b", Command::Probe, NOW + 100))?,
        Outcome::AlreadyDelivered
    ));
    Ok(())
}

fn uncertainty_and_guards(f: &SessionFixture) -> TestResult {
    let first = permit(f.apply(&f.claim("a", "owner", NOW, Some(f.candidate("a", NOW)?)))?)?;
    assert_eq!(first.deadline, NOW + 7);
    assert!(matches!(
        f.apply(&f.request("a", Command::Check(first.clone()), NOW + 7))?,
        Outcome::Deferred
    ));
    assert!(matches!(
        f.apply(&f.claim("a", "early", NOW + 11, None))?,
        Outcome::Deferred
    ));
    let second = permit(f.apply(&f.claim("a", "new-owner", NOW + 12, None))?)?;
    assert!(first.token == second.token);
    assert!(matches!(
        f.apply(&f.request("a", Command::Check(first.clone()), NOW + 12))?,
        Outcome::Deferred
    ));
    assert!(matches!(
        f.apply(&f.request(
            "a",
            Command::Complete(first.clone(), Completion::Delivered),
            NOW + 12
        ))?,
        Outcome::Deferred
    ));
    assert!(f
        .apply(&f.request("a", Command::Check(second.clone()), NOW + 11))
        .is_err());
    let mut wrong = f.request("a", Command::Probe, NOW + 12);
    wrong.identity.subject = "wrong".to_string();
    assert!(f.apply(&wrong).is_err());
    wrong.identity.subject = "subject".to_string();
    wrong.identity.event_jti = "wrong".to_string();
    assert!(f.apply(&wrong).is_err());
    assert!(f
        .apply(&f.request("unassociated", Command::Probe, NOW + 12))
        .is_err());
    assert!(matches!(
        f.apply(&f.request(
            "a",
            Command::Complete(second, Completion::Delivered),
            NOW + 12
        ))?,
        Outcome::Completed
    ));
    assert!(matches!(
        f.apply(&f.request("a", Command::Probe, NOW + 13))?,
        Outcome::AlreadyDelivered
    ));
    assert!(matches!(
        f.apply(&f.request(
            "a",
            Command::Complete(first, Completion::Delivered),
            NOW + 13
        ))?,
        Outcome::Deferred
    ));
    Ok(())
}

#[test]
fn logout_delivery_local_attempt_budget_and_identity() -> TestResult {
    attempts_and_identity(&SessionFixture::local(600)?)
}
#[test]
fn logout_delivery_local_uncertainty_ownership_and_rollback() -> TestResult {
    uncertainty_and_guards(&SessionFixture::local(600)?)
}
#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_attempt_budget_and_identity() -> TestResult {
    attempts_and_identity(&SessionFixture::redis(600)?)
}
#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_uncertainty_ownership_and_rollback() -> TestResult {
    uncertainty_and_guards(&SessionFixture::redis(600)?)
}

#[test]
fn logout_delivery_local_horizons_and_registration_changes() -> TestResult {
    for ttl in [8, 600] {
        let f = SessionFixture::local(ttl)?;
        let p = permit(f.apply(&f.claim("a", "owner", NOW, Some(f.candidate("a", NOW)?)))?)?;
        assert_eq!(p.horizon, NOW + ttl.min(300));
        assert!(matches!(
            f.apply(&f.request(
                "a",
                Command::Complete(
                    p,
                    Completion::Recoverable {
                        retry_after: Some(NOW + ttl.min(300))
                    }
                ),
                NOW
            ))?,
            Outcome::Terminal
        ));
        assert!(matches!(
            f.apply(&f.request("b", Command::Probe, NOW + ttl))?,
            Outcome::Terminal
        ));
    }
    let f = SessionFixture::local(600)?;
    let p = permit(f.apply(&f.claim("a", "owner", NOW, Some(f.candidate("a", NOW)?)))?)?;
    let mut changed = f.request("a", Command::Check(p.clone()), NOW);
    changed.binding.as_mut().expect("binding").session_required = true;
    assert!(matches!(f.apply(&changed)?, Outcome::Terminal));
    assert!(matches!(
        f.apply(&f.request("a", Command::Complete(p, Completion::Delivered), NOW))?,
        Outcome::Deferred
    ));
    Ok(())
}

fn stale_owner_preserves_newer_results(
    factory: fn(u64) -> TestResult<SessionFixture>,
) -> TestResult {
    for result in [
        Completion::Delivered,
        Completion::Terminal,
        Completion::Recoverable { retry_after: None },
    ] {
        let f = factory(600)?;
        let first =
            permit(f.apply(&f.claim("a", "owner-1", NOW, Some(f.candidate("a", NOW)?)))?)?;
        let second = permit(
            f.b.delivery_transition(&f.claim("a", "owner-2", NOW + 12, None))
                .map_err(anyhow::Error::msg)?,
        )?;
        f.apply(&f.request("a", Command::Complete(second, result.clone()), NOW + 12))?;
        let snapshot = || -> TestResult<Option<String>> {
            let Some((url, prefix)) = &f.redis else {
                return Ok(None);
            };
            let mut conn = ::redis::Client::open(url.as_str())?.get_connection()?;
            Ok(Some(
                ::redis::cmd("HGET")
                    .arg(format!("{prefix}:session:{}", f.event.sid))
                    .arg(crate::oidc::session::delivery::recipient_field("a"))
                    .query(&mut conn)?,
            ))
        };
        let original = snapshot()?;
        for command in [
            Command::Check(first.clone()),
            Command::Complete(first.clone(), Completion::Delivered),
        ] {
            let mut stale = f.request("a", command, NOW + 13);
            stale.binding.as_mut().expect("binding").uri =
                "https://changed.example/logout".to_string();
            assert!(matches!(f.apply(&stale)?, Outcome::Deferred));
            assert!(snapshot()? == original);
        }
        // A stale operation must not advance observed_at, even by one second.
        let probe = f.apply(&f.request("a", Command::Probe, NOW + 12))?;
        match result {
            Completion::Delivered => assert!(matches!(probe, Outcome::AlreadyDelivered)),
            Completion::Terminal => assert!(matches!(probe, Outcome::Terminal)),
            Completion::Recoverable { .. } => {
                assert!(matches!(probe, Outcome::Deferred));
                assert!(matches!(
                    f.apply(&f.claim("a", "early", NOW + 21, None))?,
                    Outcome::Deferred
                ));
                let third = permit(f.apply(&f.claim("a", "owner-3", NOW + 22, None))?)?;
                assert_eq!(third.attempt, 3);
                assert!(first.token == third.token);
            }
        }
    }
    // A current owner still terminally suppresses a changed registration.
    let f = factory(600)?;
    let current = permit(f.apply(&f.claim("a", "current", NOW, Some(f.candidate("a", NOW)?)))?)?;
    let mut changed = f.request("a", Command::Check(current), NOW);
    changed.binding.as_mut().expect("binding").session_required = true;
    assert!(matches!(f.apply(&changed)?, Outcome::Terminal));
    Ok(())
}

#[test]
fn logout_delivery_local_stale_owner_preserves_newer_results() -> TestResult {
    stale_owner_preserves_newer_results(SessionFixture::local)
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_stale_owner_preserves_newer_results() -> TestResult {
    stale_owner_preserves_newer_results(SessionFixture::redis)
}

fn third_attempt(f: &SessionFixture) -> TestResult<Permit> {
    let first = permit(f.apply(&f.claim("a", "first", NOW, Some(f.candidate("a", NOW)?)))?)?;
    f.apply(&f.request(
        "a",
        Command::Complete(first, Completion::Recoverable { retry_after: None }),
        NOW,
    ))?;
    let second = permit(f.apply(&f.claim("a", "second", NOW + 5, None))?)?;
    f.apply(&f.request(
        "a",
        Command::Complete(second, Completion::Recoverable { retry_after: None }),
        NOW + 5,
    ))?;
    permit(f.apply(&f.claim("a", "third", NOW + 15, None))?)
}

fn record_bytes(f: &SessionFixture) -> TestResult<Option<String>> {
    let Some((url, prefix)) = &f.redis else {
        return Ok(None);
    };
    let mut conn = ::redis::Client::open(url.as_str())?.get_connection()?;
    Ok(Some(
        ::redis::cmd("HGET")
            .arg(format!("{prefix}:session:{}", f.event.sid))
            .arg(crate::oidc::session::delivery::recipient_field("a"))
            .query(&mut conn)?,
    ))
}

fn matching_completion_after_lease(factory: fn(u64) -> TestResult<SessionFixture>) -> TestResult {
    let f = factory(600)?;
    let third = third_attempt(&f)?;
    assert_eq!((third.attempt, third.deadline), (3, NOW + 22));
    let saved = record_bytes(&f)?;
    assert!(matches!(
        f.apply(&f.request("a", Command::Check(third.clone()), NOW + 28))?,
        Outcome::Deferred
    ));
    assert!(record_bytes(&f)? == saved);
    // A prior expired Check must not advance observed_at. The matching known
    // success may arrive after lease+uncertainty without authorizing any send.
    assert!(matches!(
        f.apply(&f.request(
            "a",
            Command::Complete(third, Completion::Delivered),
            NOW + 27
        ))?,
        Outcome::Completed
    ));
    assert!(matches!(
        f.apply(&f.request("a", Command::Probe, NOW + 28))?,
        Outcome::AlreadyDelivered
    ));

    let f = factory(600)?;
    let third = third_attempt(&f)?;
    assert!(matches!(
        f.apply(&f.request("a", Command::Probe, NOW + 27))?,
        Outcome::Terminal
    ));
    let terminal = record_bytes(&f)?;
    assert!(matches!(
        f.apply(&f.request(
            "a",
            Command::Complete(third, Completion::Delivered),
            NOW + 28
        ))?,
        Outcome::Deferred
    ));
    assert!(record_bytes(&f)? == terminal);
    assert!(matches!(
        f.apply(&f.request("a", Command::Probe, NOW + 27))?,
        Outcome::Terminal
    ));

    for ttl in [40, 600] {
        let f = factory(ttl)?;
        let third = third_attempt(&f)?;
        let horizon = third.horizon;
        let saved = record_bytes(&f)?;
        assert!(matches!(
            f.apply(&f.request(
                "a",
                Command::Complete(third, Completion::Delivered),
                horizon
            ))?,
            Outcome::Terminal
        ));
        assert!(record_bytes(&f)? == saved);
        assert!(matches!(
            f.apply(&f.request("a", Command::Probe, horizon))?,
            Outcome::Terminal
        ));
    }
    Ok(())
}

#[test]
fn logout_delivery_local_matching_completion_after_lease() -> TestResult {
    matching_completion_after_lease(SessionFixture::local)
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_matching_completion_after_lease() -> TestResult {
    matching_completion_after_lease(SessionFixture::redis)
}
