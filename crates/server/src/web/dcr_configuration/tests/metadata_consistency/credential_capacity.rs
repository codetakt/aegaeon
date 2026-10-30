use super::*;
use crate::dcr_persistence::admit_http_update;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires PostgreSQL; real authority timeout, retry and outage admission"]
async fn owner_update_authority_timeout_refuses_without_restart_and_rechecks_retry() -> TestResult {
    let db = Database::create(false).await?;
    let env = setup_test_dcr_environment(&db.pool).await?;
    let mut state = test_app_state(db.pool.clone(), &env).await?;
    let restart = state.runtime_restart.clone();
    let limited = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout='200ms'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with((*db.pool.connect_options()).clone())
        .await?;
    state.db_pool = limited.clone();
    let app = crate::web::router::build_router(state);
    let mut blocker = db.pool.begin().await?;
    sqlx::query("LOCK TABLE aegaeon.clients IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let timeout_result = async {
        let response = tokio::time::timeout(
            Duration::from_secs(4),
            app.clone().oneshot(request(
                Method::PUT,
                "/register/untrusted",
                None,
                &json!({}),
            )?),
        )
        .await??;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response_json(response).await?["error"],
            "temporarily_unavailable"
        );
        assert!(
            !restart.is_requested(),
            "request budget must not latch a process restart"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    blocker.rollback().await?;
    let result = async {
        timeout_result?;
        // The next request reads the live database again before authentication.
        let response = app
            .clone()
            .oneshot(request(
                Method::PUT,
                "/register/untrusted",
                None,
                &json!({}),
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!restart.is_requested());
        // General store failure still uses the established process-stop policy.
        limited.close().await;
        let response = app
            .oneshot(request(
                Method::PUT,
                "/register/untrusted",
                None,
                &json!({}),
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(restart.is_requested());
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    limited.close().await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

async fn scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let app = router(pool, env).await?;
    let current = post(
        &app,
        &json!({"redirect_uris":["https://client.example/callback"],
        "token_endpoint_auth_method":"client_secret_basic", "pkce_required":true}),
    )
    .await?;
    let id = field(&current, "client_id")?;
    let token = field(&current, "registration_access_token")?;
    let before = digest(pool, env).await?;
    // Exhaust the real shared pool. An admission layer behind authority or
    // authentication middleware cannot answer these requests before the deadline.
    let mut held = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        held.push(pool.acquire().await?);
    }
    admit_http_update(async {
        admit_http_update(async {
            for (token, body) in [
                (Some(token), "{}"),
                (Some("wrong-token"), "{malformed"),
                (None, "{}"),
                (Some(token), "{\"client_secret\":\"untrusted\"}"),
            ] {
                let mut builder = Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/register/{id}"))
                    .header(header::CONTENT_TYPE, "application/json");
                if let Some(token) = token {
                    builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
                }
                let response = tokio::time::timeout(
                    Duration::from_secs(2),
                    app.clone().oneshot(builder.body(Body::from(body))?),
                )
                .await??;
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
                assert_eq!(
                    response_json(response).await?["error"],
                    "temporarily_unavailable"
                );
            }
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                app.clone()
                    .oneshot(Request::builder().uri("/health").body(Body::empty())?),
            )
            .await??;
            assert_eq!(response.status(), StatusCode::OK);
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await?
    })
    .await??;
    drop(held);
    assert_eq!(before, digest(pool, env).await?);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/register/{id}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer wrong-token")
                .body(Body::from("{malformed"))?,
        )
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "authentication precedence after admission"
    );
    // One other request already holds admission: the HTTP update must reuse its
    // own second slot in persistence, rather than trying to acquire a third slot.
    admit_http_update(async {
        credential_admission::accepted(
            &app,
            &current,
            &json!({"client_id":id,
            "client_secret":field(&current, "client_secret")?,"pkce_required":true}),
        )
        .await
    })
    .await??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; mounted router capacity before database middleware"]
async fn owner_update_capacity_precedes_database_and_preserves_admitted_authentication(
) -> TestResult {
    let db = Database::create(false).await?;
    let result = async {
        let env = setup_test_dcr_environment(&db.pool).await?;
        scenario(&db.pool, &env).await
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; incomplete and trickling real HTTP owner bodies"]
async fn owner_update_body_absolute_deadline_recovers_both_slots() -> TestResult {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let db = Database::create(false).await?;
    let env = setup_test_dcr_environment(&db.pool).await?;
    let app = router(&db.pool, &env).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let service = app.clone();
    let server = tokio::spawn(async move { axum::serve(listener, service).await });
    let result = async {
        let before = digest(&db.pool, &env).await?;
        let mut readers = Vec::new();
        let mut writers = Vec::new();
        for drip in [false, true] {
            let mut socket = tokio::net::TcpStream::connect(address).await?;
            socket.write_all(b"PUT /register/untrusted HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await?;
            let (read, mut write) = socket.into_split();
            readers.push(read);
            writers.push(tokio::spawn(async move {
                if drip {
                    loop {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        if write.write_all(b"1\r\n \r\n").await.is_err() { break; }
                    }
                } else { std::future::pending::<()>().await; }
            }));
        }
        let checks = async {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if admit_http_update(async {}).await.is_err() { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await?;
            let overloaded = app.clone().oneshot(request(Method::PUT, "/register/untrusted", None, &json!({}))?).await?;
            assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
            for mut reader in readers {
                let mut response = String::new();
                tokio::time::timeout(Duration::from_secs(13), reader.read_to_string(&mut response)).await??;
                assert!(response.starts_with("HTTP/1.1 408"), "{response}");
                assert!(response.contains("cache-control: no-store"), "{response}");
            }
            let recovered = app.clone().oneshot(request(Method::PUT, "/register/untrusted", None, &json!({}))?).await?;
            assert_eq!(recovered.status(), StatusCode::UNAUTHORIZED);
            let oversized = app.oneshot(Request::builder().method(Method::PUT).uri("/register/untrusted")
                .body(Body::from(vec![b' '; crate::web::router::SERVER_REQUEST_BODY_LIMIT_BYTES + 1]))?).await?;
            assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(before, digest(&db.pool, &env).await?);
            Ok::<(), Box<dyn std::error::Error>>(())
        }.await;
        for writer in writers { writer.abort(); let _ = writer.await; }
        checks
    }.await;
    server.abort();
    let _ = server.await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
