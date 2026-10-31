use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use std::time::{Duration, Instant};

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_browser_pre_authority_capacity_cancel_failure_and_recovery(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured(&f).await?;
    let witness = CallerFixture::new(state.environment_id).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
        let uri = authorize(&state, &key)?;
        let (status, html) = admitted_page(&witness, &state, &sid, &uri, None).await?;
        assert_eq!(status, StatusCode::OK, "{html}");
        let token = transaction(&html)?.to_owned();
        let all = crate::web::browser_authorization_admission::reserve_for_test()?;
        assert_eq!(
            admitted_page(&witness, &state, &sid, &uri, None).await?.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            admitted_page(
                &witness,
                &state,
                &sid,
                "/auth/consent",
                Some(&[("transaction", &token), ("decision", "approve")])
            )
            .await?
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(all);
        for (consent, store) in [
            (false, "session"),
            (true, "session"),
            (false, "rate"),
            (false, "stepup"),
            (true, "stepup"),
        ] {
            for cancel in [false, true] {
                let (url, received, peer) = store_fault::stalled_peer()?;
                let mut failed = state.clone();
                let namespace =
                    crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
                if store == "rate" {
                    failed.device.local_login_rate_limiter = Arc::new(
                        crate::device_authz::VerificationRateLimiter::redis_for_tests(
                            &url, &namespace,
                        )?,
                    );
                } else if store == "stepup" {
                    failed.protocol.stepup_store = Arc::new(
                        crate::stepup::StepUpStore::redis_for_tests(&url, &namespace)?,
                    );
                } else {
                    failed.browser_auth.auth_sessions = Arc::new(
                        crate::web::AuthSessionStore::redis_for_tests(&url, &namespace)?,
                    );
                }
                failed.validate_subject_namespace().await?;
                let task_uri = uri.clone();
                let task_sid = sid.clone();
                let task_token = token.clone();
                let started = Instant::now();
                // This subcase isolates browser capacity before authority use.
                // The deliberately unscoped failed store must refuse before
                // any protected consent is read or issued. It does not model
                // reconciliation of uncertain epoch-owned store work.
                let request = tokio::spawn(async move {
                    let form = [
                        ("transaction", task_token.as_str()),
                        ("decision", "approve"),
                    ];
                    page(
                        &failed,
                        &task_sid,
                        if consent { "/auth/consent" } else { &task_uri },
                        consent.then_some(form.as_slice()),
                    )
                    .await
                    .map(|r| r.0)
                    .map_err(|e| e.to_string())
                });
                tokio::time::timeout(Duration::from_secs(3), received).await??;
                assert!(
                    started.elapsed() < Duration::from_secs(2),
                    "browser store blocked executor"
                );
                assert!(crate::web::browser_authorization_admission::reserve_for_test().is_err());
                if cancel {
                    request.abort();
                    assert!(request.await.unwrap_err().is_cancelled());
                    assert!(
                        crate::web::browser_authorization_admission::reserve_for_test().is_err(),
                        "cancel released running browser work"
                    );
                } else {
                    assert_eq!(
                        tokio::time::timeout(Duration::from_secs(8), request).await???,
                        StatusCode::SERVICE_UNAVAILABLE
                    );
                }
                tokio::task::spawn_blocking(move || peer.join().unwrap()).await?;
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    if let Ok(all) = crate::web::browser_authorization_admission::reserve_for_test()
                    {
                        drop(all);
                        break;
                    }
                    assert!(Instant::now() < deadline, "browser owner did not finish");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let (status, body) = admitted_page(&witness, &state, &sid, &uri, None).await?;
                assert_eq!(status, StatusCode::OK, "recovery: {body}");
            }
        }
        let (status, body) = admitted_page(
            &witness,
            &state,
            &sid,
            "/auth/consent",
            Some(&[("transaction", &token), ("decision", "approve")]),
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "pending approval survives pre-load failures: {body}"
        );
        assert!(code(&body, &state.issuer).is_ok());
        Ok(())
    }
    .await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() });
    fixture::finish(&state).await?;
    f.cleanup(result.and(cleanup)).await
}

async fn admitted_page(
    witness: &CallerFixture,
    state: &AppState,
    sid: &str,
    uri: &str,
    form: Option<&[(&str, &str)]>,
) -> TestResult<(StatusCode, String)> {
    let work = witness.begin().await?;
    let response = work
        .store_scope(Box::pin(page(state, sid, uri, form)))
        .await??;
    assert_eq!(work.complete().await?.pending, 0);
    Ok(response)
}
