use super::*;
use crate::dcr_persistence::admit_http_update;
use std::time::Duration;

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
