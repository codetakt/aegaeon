use super::*;

#[tokio::test]
async fn notification_tls_malformed_204_framing_is_uncertain() -> anyhow::Result<()> {
    for chunked in [false, true] {
        let fixture = fixture::Fixture::malformed_empty_acknowledgement(chunked)?;
        let endpoint = "https://delivery.example.test/envelopes";
        let client =
            client(endpoint, &trust::Trust::default()).map_err(|_| anyhow::anyhow!("client"))?;
        let credential = Credential::parse(URL_SAFE_NO_PAD.encode([7; 32]))
            .map_err(|_| anyhow::anyhow!("credential"))?;
        let observed = send(
            &client,
            endpoint,
            Uuid::new_v4(),
            Zeroizing::new(b"{}".to_vec()),
            &credential,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(observed.outcome, TransportOutcome::Uncertain, "{chunked}");
        assert_eq!(observed.retry_after, Some(RetryAfter::DelaySeconds(3600)));
        assert_eq!(fixture.received.lock().unwrap().len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn notification_tls_body_failures_keep_retry_after_lower_bound() -> anyhow::Result<()> {
    use crate::organizations::notification_retry::{plan, CompletedAttempt, RetryPlan};
    // Declared oversize, chunked oversize, truncated body, and body deadline:
    // all use real rustls/HTTP connections through the production sender.
    for kind in 0..4 {
        let fixture = fixture::Fixture::retry_after_body_failure(kind)?;
        let endpoint = "https://delivery.example.test/envelopes";
        let client =
            client(endpoint, &trust::Trust::default()).map_err(|_| anyhow::anyhow!("client"))?;
        let credential = Credential::parse(URL_SAFE_NO_PAD.encode([7; 32]))
            .map_err(|_| anyhow::anyhow!("credential"))?;
        let observed = send(
            &client,
            endpoint,
            Uuid::new_v4(),
            Zeroizing::new(b"{}".to_vec()),
            &credential,
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(observed.outcome, TransportOutcome::Uncertain, "{kind}");
        assert_eq!(
            observed.retry_after,
            Some(RetryAfter::DelaySeconds(3600)),
            "{kind}"
        );
        assert_eq!(
            plan(
                CompletedAttempt {
                    attempts: 1,
                    observed_at: 100,
                    outcome: observed.outcome,
                    retry_after: observed.retry_after
                },
                4000,
                0
            ),
            Ok(RetryPlan::At(3700))
        );
        assert_eq!(fixture.received.lock().unwrap().len(), 1);
    }
    Ok(())
}

#[test]
fn notification_retry_after_preserves_delay_and_date_lower_bounds() {
    for (text, expected) in [
        ("60", Some(RetryAfter::DelaySeconds(60))),
        (" 00060\t", Some(RetryAfter::DelaySeconds(60))),
        (
            "18446744073709551616",
            Some(RetryAfter::DelaySeconds(u64::MAX)),
        ),
        (
            "Sun, 06 Nov 1994 08:49:37 GMT",
            Some(RetryAfter::UnixSeconds(784111777)),
        ),
        ("-1", None),
        ("+1", None),
        ("1.0", None),
        ("1, 2", None),
        ("", None),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_str(text).unwrap());
        assert_eq!(parse_retry_after(&headers), expected, "{text}");
    }
    let mut duplicate = HeaderMap::new();
    duplicate.append(RETRY_AFTER, HeaderValue::from_static("60"));
    duplicate.append(RETRY_AFTER, HeaderValue::from_static("120"));
    assert_eq!(parse_retry_after(&duplicate), None);
}

#[tokio::test]
async fn notification_tls_retries_reuse_message_and_exact_payload() -> anyhow::Result<()> {
    let fixture = fixture::Fixture::lose_first_reply()?;
    let endpoint = "https://delivery.example.test/envelopes";
    let client =
        client(endpoint, &trust::Trust::default()).map_err(|_| anyhow::anyhow!("client"))?;
    let credential = Credential::parse(URL_SAFE_NO_PAD.encode([7; 32]))
        .map_err(|_| anyhow::anyhow!("credential"))?;
    let id = Uuid::new_v4();
    let bytes = serde_json::to_vec(
        &serde_json::json!({"version":2,"messageId":id,"capability":"fixture-proof"}),
    )?;
    for expected in [TransportOutcome::Uncertain, TransportOutcome::Accepted] {
        let observation = send(
            &client,
            endpoint,
            id,
            Zeroizing::new(bytes.clone()),
            &credential,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(observation.outcome, expected);
    }
    let records = fixture.received.lock().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0], records[1]);
    assert_eq!(records[0]["fixtureMessageId"], id.to_string());
    assert_eq!(
        records[0]["fixturePayloadDigest"],
        crate::subject_ownership::history::sha256_hex(&bytes)
    );
    assert_eq!(records[0]["fixtureAuthorizationPresent"], true);
    Ok(())
}

#[tokio::test]
async fn notification_tls_outcomes_refuse_redirects_and_bound_responses() -> anyhow::Result<()> {
    for (status, body, wrong_name, expected) in [
        (302, vec![], false, TransportOutcome::Rejected),
        (400, vec![], false, TransportOutcome::Rejected),
        (408, vec![], false, TransportOutcome::Uncertain),
        (429, vec![], false, TransportOutcome::Retryable),
        (503, vec![], false, TransportOutcome::Retryable),
        (200, vec![], false, TransportOutcome::Uncertain),
        (503, vec![0; 1025], false, TransportOutcome::Uncertain),
        (204, vec![], true, TransportOutcome::Uncertain),
    ] {
        let fixture = fixture::Fixture::new(status, body, Duration::ZERO, wrong_name)?;
        let endpoint = "https://delivery.example.test/envelopes";
        let client =
            client(endpoint, &trust::Trust::default()).map_err(|_| anyhow::anyhow!("client"))?;
        let credential = Credential::parse(URL_SAFE_NO_PAD.encode([7; 32]))
            .map_err(|_| anyhow::anyhow!("credential"))?;
        let observed = send(
            &client,
            endpoint,
            Uuid::new_v4(),
            Zeroizing::new(b"{}".to_vec()),
            &credential,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(observed.outcome, expected, "{status}/{wrong_name}");
        assert_eq!(
            fixture.received.lock().unwrap().len(),
            usize::from(!wrong_name)
        );
    }
    Ok(())
}
