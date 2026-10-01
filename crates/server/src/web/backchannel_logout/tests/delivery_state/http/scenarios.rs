use super::*;

fn status_and_retry_after(factory: fn(u64) -> TestResult<SessionFixture>) -> TestResult {
    runtime_test(async {
        for code in [400, 202, 302, 404, 501] {
            let mut f = factory(600)?;
            f.event.client_ids = vec!["a".to_string()];
            let http = HttpFixture::new(&[("a", vec![Reply::Status(code, vec![])])]).await?;
            let result = http.send(&f, false, NOW).await;
            assert_eq!((result.delivered, result.terminal_undelivered), (0, 1));
            assert_eq!(http.send(&f, true, NOW + 5).await.sent, 0);
            assert_eq!(http.tokens().len(), 1);
        }
        for code in [408, 429, 500, 502, 503, 504] {
            let mut f = factory(600)?;
            f.event.client_ids = vec!["a".to_string()];
            let http = HttpFixture::new(&[("a", vec![Reply::Status(code, vec![])])]).await?;
            assert_eq!(http.send(&f, false, NOW).await.deferred, 1);
            assert_eq!(http.send(&f, true, NOW + 4).await.sent, 0);
            assert_eq!(http.send(&f, true, NOW + 5).await.delivered, 1);
            let tokens = http.tokens();
            assert!(tokens[0].1 == tokens[1].1);
        }
        for (header, due) in [("10", 10), ("Tue, 14 Nov 2023 22:13:40 GMT", 20), ("0", 5)] {
            let mut f = factory(600)?;
            f.event.client_ids = vec!["a".to_string()];
            let http =
                HttpFixture::new(&[("a", vec![Reply::Status(503, vec![header.to_string()])])])
                    .await?;
            assert_eq!(http.send(&f, false, NOW).await.deferred, 1);
            assert_eq!(http.send(&f, true, NOW + due - 1).await.sent, 0);
            assert_eq!(http.send(&f, true, NOW + due).await.delivered, 1);
        }
        Ok(())
    })
}

fn invalid_retry_after(factory: fn(u64) -> TestResult<SessionFixture>) -> TestResult {
    runtime_test(async {
        for headers in [
            vec!["1", "2"],
            vec![""],
            vec!["not-a-date"],
            vec!["18446744073709551615"],
            vec!["300"],
            vec!["600"],
        ] {
            let mut f = factory(600)?;
            f.event.client_ids = vec!["a".to_string()];
            let http = HttpFixture::new(&[(
                "a",
                vec![Reply::Status(
                    503,
                    headers.into_iter().map(str::to_string).collect(),
                )],
            )])
            .await?;
            assert_eq!(http.send(&f, false, NOW).await.terminal_undelivered, 1);
            assert_eq!(http.send(&f, true, NOW + 20).await.sent, 0);
            assert_eq!(http.tokens().len(), 1);
        }
        let mut f = factory(8)?;
        f.event.client_ids = vec!["a".to_string()];
        let http =
            HttpFixture::new(&[("a", vec![Reply::Status(503, vec!["8".to_string()])])]).await?;
        assert_eq!(http.send(&f, false, NOW).await.terminal_undelivered, 1);
        assert_eq!(http.send(&f, true, NOW + 8).await.sent, 0);
        Ok(())
    })
}

#[test]
fn logout_delivery_http_changed_registration_and_disabled_policy() -> TestResult {
    runtime_test(async {
        let mut f = SessionFixture::local(600)?;
        f.event.client_ids = vec!["a".to_string()];
        let mut http = HttpFixture::new(&[("a", vec![Reply::Status(503, vec![])])]).await?;
        http.cfg.backchannel_logout_enabled = false;
        assert_eq!(http.send(&f, false, NOW).await.disabled_clients, 1);
        assert!(http.tokens().is_empty());
        http.cfg.backchannel_logout_enabled = true;
        assert_eq!(http.send(&f, false, NOW).await.deferred, 1);
        http.clients.register(super::super::super::delivery::client(
            "a",
            "https://rp.example/changed",
            true,
        ));
        assert_eq!(http.send(&f, true, NOW + 5).await.terminal_undelivered, 1);
        assert_eq!(http.tokens().len(), 1);
        Ok(())
    })
}

async fn loss_and_cancellation(mut f: SessionFixture) -> TestResult {
    f.event.client_ids = vec!["a".to_string()];
    let mut http = HttpFixture::new(&[("a", vec![Reply::Hold])]).await?;
    http.cfg.backchannel_logout_timeout_secs = 1;
    assert_eq!(http.send(&f, false, NOW).await.deferred, 1);
    assert_eq!(http.send(&f, true, NOW + 5).await.delivered, 1);
    assert!(http.tokens()[0].1 == http.tokens()[1].1);
    // Independent recipient: cancel after the RP received bytes, before recording any response.
    f.event.client_ids = vec!["b".to_string()];
    let http = Arc::new(HttpFixture::new(&[("b", vec![Reply::Hold])]).await?);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let http_task = http.clone();
    let store = f.a.clone();
    let event = f.event.clone();
    let task = tokio::spawn(async move {
        let _ = sender.send(());
        dispatch_at(
            &http_task.cfg,
            &http_task.clients,
            Some(&store),
            &event,
            Clock {
                fixed: Some(UNIX_EPOCH + Duration::from_secs(NOW)),
            },
        )
        .await
    });
    receiver.await?;
    tokio::time::timeout(Duration::from_secs(2), http.recipient.entered.notified()).await?;
    task.abort();
    assert!(task.await.is_err());
    assert_eq!(http.send(&f, true, NOW + 11).await.sent, 0);
    assert_eq!(http.send(&f, true, NOW + 12).await.delivered, 1);
    assert!(http.tokens()[0].1 == http.tokens()[1].1);
    Ok(())
}

#[test]
fn logout_delivery_local_http_response_loss_and_cancellation() -> TestResult {
    runtime_test(async { loss_and_cancellation(SessionFixture::local(600)?).await })
}
#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_http_response_loss_and_cancellation() -> TestResult {
    runtime_test(async { loss_and_cancellation(SessionFixture::redis(600)?).await })
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_storage_failure_prevents_http_send() -> TestResult {
    use ::redis::Commands;
    runtime_test(async {
        let mut f = SessionFixture::redis(600)?;
        f.event.client_ids = vec!["a".to_string()];
        let http = HttpFixture::new(&[]).await?;
        let (url, prefix) = f.redis.as_ref().ok_or_else(|| anyhow::anyhow!("Redis"))?;
        let mut conn = ::redis::Client::open(url.as_str())?.get_connection()?;
        let key = format!("{prefix}:session:{}", f.event.sid);
        conn.set::<_, _, ()>(&key, "corrupt-parent-type")?;
        assert_eq!(http.send(&f, false, NOW).await.storage_failures, 1);
        assert!(http.tokens().is_empty());
        conn.del::<_, ()>(&key)?;
        Ok(())
    })
}

#[test]
fn logout_delivery_http_status_and_retry_after_boundaries() -> TestResult {
    status_and_retry_after(SessionFixture::local)
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_http_status_and_retry_after_boundaries() -> TestResult {
    status_and_retry_after(SessionFixture::redis)
}

#[test]
fn logout_delivery_http_invalid_retry_after_and_horizon_are_terminal() -> TestResult {
    invalid_retry_after(SessionFixture::local)
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_http_invalid_retry_after_and_horizon_are_terminal() -> TestResult {
    invalid_retry_after(SessionFixture::redis)
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_successful_response_with_failed_completion_is_unknown() -> TestResult {
    use ::redis::Commands;
    runtime_test(async {
        let mut f = SessionFixture::redis(600)?;
        f.event.client_ids = vec!["a".to_string()];
        let (url, prefix) = f.redis.as_ref().ok_or_else(|| anyhow::anyhow!("Redis"))?;
        let key = format!("{prefix}:session:{}", f.event.sid);
        let (callback_url, callback_key) = (url.clone(), key.clone());
        let callback = Arc::new(move || {
            let mut conn = ::redis::Client::open(callback_url.as_str())
                .expect("fixture client")
                .get_connection()
                .expect("fixture connection");
            conn.set::<_, _, ()>(&callback_key, "unavailable-parent-type")
                .expect("scoped failure injection");
        });
        let http = HttpFixture::new(&[("a", vec![Reply::BeforeAck(callback)])]).await?;
        let report = http.send(&f, false, NOW).await;
        assert_eq!(
            (
                report.sent,
                report.delivered,
                report.storage_failures,
                report.unknown_outcomes
            ),
            (1, 0, 1, 1)
        );
        assert_eq!(http.tokens().len(), 1);
        let mut conn = ::redis::Client::open(url.as_str())?.get_connection()?;
        conn.del::<_, ()>(&key)?;
        Ok(())
    })
}

fn delivered_history_survives_token_expiry(
    factory: fn(u64) -> TestResult<SessionFixture>,
) -> TestResult {
    runtime_test(async {
        let mut f = factory(600)?;
        f.event.client_ids = vec!["a".to_string()];
        let http = HttpFixture::new(&[]).await?;
        assert_eq!(http.send(&f, false, NOW).await.delivered, 1);
        for time in [NOW + 300, NOW + 301, NOW + 599] {
            let report = http.send(&f, true, time).await;
            assert_eq!(
                (
                    report.sent,
                    report.delivered,
                    report.already_delivered,
                    report.terminal_undelivered
                ),
                (0, 0, 1, 0)
            );
            assert!(matches!(
                f.apply(&f.claim("a", "stale-event", time, None))?,
                Outcome::AlreadyDelivered
            ));
        }
        let expired = http.send(&f, true, NOW + 600).await;
        assert_eq!(
            (
                expired.sent,
                expired.already_delivered,
                expired.terminal_undelivered
            ),
            (0, 0, 1)
        );
        f.a.prune_expired_at(NOW + 600);
        let missing = http.send(&f, false, NOW + 601).await;
        assert_eq!(
            (
                missing.sent,
                missing.already_delivered,
                missing.legacy_unknown
            ),
            (0, 0, 1)
        );
        assert_eq!(http.tokens().len(), 1);
        Ok(())
    })
}

#[test]
fn logout_delivery_local_success_history_outlives_token() -> TestResult {
    delivered_history_survives_token_expiry(SessionFixture::local)
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_success_history_outlives_token() -> TestResult {
    delivered_history_survives_token_expiry(SessionFixture::redis)
}
