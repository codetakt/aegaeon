use super::*;
use crate::web::backchannel_logout::{delivery::dispatch_with_uri_validation, DispatchUriError};
use std::sync::atomic::{AtomicUsize, Ordering};

fn resolution_recovery(factory: fn(u64) -> TestResult<SessionFixture>) -> TestResult {
    runtime_test(async {
        for retry in [false, true] {
            for unavailable_at in 1..=3 {
                let mut f = factory(600)?;
                f.event.client_ids = vec!["a".to_string()];
                let replies = if retry {
                    vec![Reply::Status(503, vec![]), Reply::Status(204, vec![])]
                } else {
                    vec![Reply::Status(204, vec![])]
                };
                let http = HttpFixture::new(&[("a", replies)]).await?;
                if retry {
                    assert_eq!(http.send(&f, false, NOW).await.deferred, 1);
                }
                let calls = AtomicUsize::new(0);
                let validation = |uri: &str| {
                    if calls.fetch_add(1, Ordering::SeqCst) + 1 == unavailable_at {
                        Err(DispatchUriError::from(
                            crate::ssrf::SsrfError::DnsResolutionFailed(
                                "temporary fixture failure".into(),
                            ),
                        ))
                    } else {
                        validate_backchannel_logout_dispatch_uri(uri)
                    }
                };
                let report = dispatch_with_uri_validation(
                    &http.cfg,
                    &http.clients,
                    Some(&f.b),
                    &f.event,
                    Clock {
                        fixed: Some(UNIX_EPOCH + Duration::from_secs(NOW + 5)),
                    },
                    &validation,
                )
                .await;
                assert_eq!(calls.load(Ordering::SeqCst), unavailable_at);
                assert_eq!(
                    (report.sent, report.deferred, report.terminal_undelivered),
                    (0, 1, 0)
                );
                assert_eq!(
                    (report.storage_failures, report.rejected_logout_uri),
                    (0, 0)
                );
                assert_eq!(http.tokens().len(), usize::from(retry));
                // Recovery uses the same registration, remaining retry budget and
                // canonical token; no terminal record is written during DNS loss.
                assert_eq!(http.send(&f, false, NOW + 20).await.delivered, 1);
                let tokens = http.tokens();
                if retry {
                    assert_eq!(tokens[0].1, tokens[1].1);
                }
                assert_eq!(http.send(&f, true, NOW + 21).await.already_delivered, 1);
            }
        }
        Ok(())
    })
}

#[test]
fn logout_delivery_local_dns_failure_defers_initial_and_retry_at_every_uri_check() -> TestResult {
    resolution_recovery(SessionFixture::local)
}

#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_dns_failure_defers_initial_and_retry_at_every_uri_check() -> TestResult {
    resolution_recovery(SessionFixture::redis)
}

#[test]
fn logout_delivery_uri_policy_refusal_remains_terminal() -> TestResult {
    runtime_test(async {
        let mut f = SessionFixture::local(600)?;
        f.event.client_ids = vec!["a".to_string()];
        let http = HttpFixture::new(&[]).await?;
        let validation = |_uri: &str| {
            Err(DispatchUriError::from(
                crate::ssrf::SsrfError::NonRoutableIp("blocked fixture address".into()),
            ))
        };
        let report = dispatch_with_uri_validation(
            &http.cfg,
            &http.clients,
            Some(&f.a),
            &f.event,
            Clock {
                fixed: Some(UNIX_EPOCH + Duration::from_secs(NOW)),
            },
            &validation,
        )
        .await;
        assert_eq!(
            (report.rejected_logout_uri, report.terminal_undelivered),
            (1, 1)
        );
        assert_eq!(
            (report.sent, report.deferred, report.storage_failures),
            (0, 0, 0)
        );
        assert_eq!(http.send(&f, true, NOW + 20).await.terminal_undelivered, 1);
        assert!(http.tokens().is_empty());
        Ok(())
    })
}
