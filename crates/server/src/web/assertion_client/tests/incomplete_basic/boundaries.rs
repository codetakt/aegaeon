use super::*;
use axum::extract::{Form, OriginalUri, State};

async fn earlier_admission(state: &AppState) -> TestResult {
    for path in PATHS {
        let mut f = password_fields(path, BASIC);
        f.push(("client_id".into(), BASIC.into()));
        reject_request(state, path, &borrowed(&f), Some("Basic")).await?;
        let app = crate::web::router::build_router(state.clone()).layer(Extension(ConnectInfo(
            SocketAddr::from(([127, 0, 0, 1], 12345)),
        )));
        for (uri, content_type) in [
            (path.to_owned(), "application/json"),
            (
                format!("{path}?client_secret=synthetic"),
                "application/x-www-form-urlencoded",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(uri)
                        .header(header::CONTENT_TYPE, content_type)
                        .header(header::AUTHORIZATION, "Basic")
                        .body(Body::from(serde_urlencoded::to_string(password_fields(
                            path, BASIC,
                        ))?))?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_client_challenge(path, response.headers(), false)?;
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
            assert_eq!(body["error"], "invalid_request");
        }
    }
    reject_request(state, "/token", &[("client_id", BASIC)], Some("Basic")).await?;
    Ok(())
}

async fn par_outer_id_precedence(state: &AppState) -> TestResult {
    let mut f = password_fields("/par", BASIC);
    f.retain(|(key, _)| key != "client_id");
    for auth in incomplete_headers() {
        reject(state, "/par", &borrowed(&f), Some(&auth)).await?;
    }
    // Decodable credentials still require the existing plain-PAR outer identity.
    reject_request(state, "/par", &borrowed(&f), Some(&basic())).await
}

async fn snapshot_precedence(state: &AppState) -> TestResult {
    // Direct production handler invocation isolates the endpoint snapshot failure
    // from the router's earlier runtime-authority guard, which may inspect locks.
    state.clients.poison_request_snapshot_for_test();
    assert!(state.clients.try_request_snapshot(&[BASIC]).is_err());
    let mut cases = incomplete_headers()
        .into_iter()
        .map(|h| (h, true))
        .collect::<Vec<_>>();
    cases.push((basic(), false));
    for (auth, incomplete) in cases {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse()?,
        );
        headers.insert(header::AUTHORIZATION, auth.parse()?);
        let response = crate::web::token_lifecycle::introspect(
            State(state.clone()),
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))),
            OriginalUri("/introspect".parse()?),
            headers,
            Ok(Form(password_fields("/introspect", BASIC))),
        )
        .await;
        assert_eq!(
            response.status(),
            if incomplete {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        );
        assert_client_challenge("/introspect", response.headers(), incomplete)?;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(
            body["error"],
            if incomplete {
                "invalid_client"
            } else {
                "temporarily_unavailable"
            }
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn incomplete_basic_keeps_earlier_admission_and_precedes_par_identity_and_snapshot(
) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        earlier_admission(&state).await?;
        par_outer_id_precedence(&state).await?;
        snapshot_precedence(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
