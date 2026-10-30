use super::*;
use std::time::{Duration, Instant};

pub(super) async fn post_form(
    state: &AppState,
    path: &str,
    fields: &[(String, String)],
    proof: &str,
) -> TestResult<StatusCode> {
    let mut request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{OWNER}:{SECRET}"))),
        )
        .header("DPoP", proof)
        .body(Body::from(serde_urlencoded::to_string(fields)?))?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
    let response = crate::web::build_router(state.clone())
        .oneshot(request)
        .await?;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = to_bytes(response.into_body(), 65536).await?;
    assert!(
        matches!(
            status,
            StatusCode::OK
                | StatusCode::CREATED
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::INTERNAL_SERVER_ERROR
        ),
        "{path}: {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(status)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_token_par_proof_capacity_fault_and_recovery() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&f).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let parent = fixture::parent(&f, &state, &key).await?;
        let token_fields = vec![
            ("grant_type".into(), TOKEN_EXCHANGE_GRANT_TYPE.into()),
            (
                "subject_token".into(),
                parent["access_token"].as_str().ok_or("parent")?.into(),
            ),
            (
                "subject_token_type".into(),
                "urn:ietf:params:oauth:token-type:access_token".into(),
            ),
            ("audience".into(), "management-api".into()),
            ("authorization_details".into(), selection(IDENTIFIER)),
        ];
        let par_fields = vec![
            ("client_id".into(), OWNER.into()),
            ("state".into(), "proof-worker-state".into()),
            ("iss".into(), state.issuer.as_str().into()),
            ("response_type".into(), "code".into()),
            ("redirect_uri".into(), "https://example.test/cb".into()),
            ("scope".into(), "read".into()),
            (
                "code_challenge".into(),
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
            ),
            ("code_challenge_method".into(), "S256".into()),
        ];
        for (path, fields, expected) in [
            ("/token", token_fields, StatusCode::OK),
            ("/par", par_fields, StatusCode::CREATED),
        ] {
            let signed = crate::web::test_support::native_dpop::proof(
                &state,
                &key,
                json!({"htu":format!("{}{path}",state.issuer)}),
            )?;
            let capacity = crate::web::token_sender_binding::reserve_for_test()?;
            assert_eq!(
                post_form(&state, path, &fields, &signed).await?,
                StatusCode::SERVICE_UNAVAILABLE
            );
            drop(capacity);
            // Saturation performed no replay mutation. The exact proof remains usable.
            assert_eq!(post_form(&state, path, &fields, &signed).await?, expected);
            let mut failed = state.clone();
            let (received, peer) = super::store_fault::stalled_replay(&mut failed)?;
            let signed = crate::web::test_support::native_dpop::proof(
                &failed,
                &key,
                json!({"htu":format!("{}{path}",failed.issuer)}),
            )?;
            let started = Instant::now();
            let request = tokio::spawn(async move {
                post_form(&failed, path, &fields, &signed)
                    .await
                    .map_err(|error| error.to_string())
            });
            received.await?;
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "proof blocked async executor"
            );
            assert!(crate::web::token_sender_binding::reserve_for_test().is_err());
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(8), request).await???,
                StatusCode::SERVICE_UNAVAILABLE
            );
            tokio::task::spawn_blocking(move || peer.join().unwrap()).await?;
            drop(crate::web::token_sender_binding::reserve_for_test()?);
        }
        Ok(())
    }
    .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
