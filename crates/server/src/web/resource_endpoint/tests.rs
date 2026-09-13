use super::*;
use crate::application_authorization::{store::capture, Authority};
use crate::authcode::types::{AccessToken, BearerTokenMeta, BearerTokenMetaInput};
use crate::metrics_integration::MetricsIntegration;
use crate::web::test_support::*;
use axum::{body::to_bytes, http::StatusCode};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

fn metrics(reason: &str) -> TestResult<(f64, f64, u64)> {
    MetricsIntegration::with_global(|integration| {
        let metrics = &integration.metrics;
        (
            metrics
                .resource_requests
                .with_label_values(&["bearer", reason])
                .get(),
            metrics
                .token_operations
                .with_label_values(&["resource_access", "bearer"])
                .get(),
            metrics
                .request_latency
                .with_label_values(&["/resource", "GET"])
                .get_sample_count(),
        )
    })
    .ok_or_else(|| "global metrics missing".into())
}

async fn request(
    state: &AppState,
    token: &str,
    status: StatusCode,
    reason: &str,
    error: Option<&str>,
) -> TestResult {
    let before = metrics(reason)?;
    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("Bearer {token}").parse()?);
    let response = resource(
        State(state.clone()),
        ConnectInfo("127.0.0.1:9000".parse()?),
        OriginalUri("/resource".parse()?),
        headers,
    )
    .await;
    let observed_status = response.status();
    if status == StatusCode::UNAUTHORIZED {
        let challenge = response.headers()["www-authenticate"].to_str()?;
        assert!(challenge.starts_with("Bearer "));
        assert!(challenge.contains("error=\"invalid_token\""));
    }
    assert!(response.headers()["cache-control"]
        .to_str()?
        .contains("no-store"));
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(observed_status, status, "{body}");
    if let Some(error) = error {
        assert_eq!(body["error"], error);
    } else {
        assert_eq!(body["status"], "granted");
    }
    let after = metrics(reason)?;
    assert_eq!(after, (before.0 + 1.0, before.1 + 1.0, before.2 + 1));
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and serial metrics observations"]
async fn pg_application_resource_rejections_record_failure_and_latency() -> TestResult {
    let integration = Arc::new(MetricsIntegration::new(Arc::new(
        aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?,
    )));
    MetricsIntegration::register_global(&integration);
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let audience = crate::resource_audience::protected_resource(&env.issuer_url);
        seed_test_projection(
            &pool,
            &env,
            "client",
            "subject",
            json!([audience]),
            json!({"roles":["USER"],"organization_roles":[]}),
        )
        .await?;
        let mut state = test_app_state(pool.clone(), &env).await?;
        state.application_authority = Some(Authority {
            projections: pool.clone(),
            memberships: None,
        });
        // This fixture uses the supported unbound Bearer policy. Scope, audience,
        // token validity and application authority checks remain enabled.
        state.tokens.validator = Arc::new(crate::authcode::TokenValidator::with_policy(
            state.tokens.store.as_ref().clone(),
            Arc::clone(&state.keys.access_token),
            crate::policy::SecurityPolicy::default()
                .with_sender_constraint(crate::policy::SenderConstraint::None),
        ));
        let access = AccessToken::new("client".into(), "subject".into(), Some("read".into()), 300);
        let token = access.token.clone();
        let mut meta = BearerTokenMeta::new(BearerTokenMetaInput {
            token_id: token.clone(),
            client_id: "client".into(),
            user_id: "subject".into(),
            granted_scopes: vec!["read".into()],
            audience,
            sender_binding: None,
            authorization_details: None,
            auth_time_epoch_secs: None,
            acr: None,
            issued_at: access.created_at,
            expires_at: access.created_at + Duration::from_secs(300),
            refresh_parent: None,
        });
        meta.application_grant = capture(
            &pool,
            env.environment_id,
            &env.issuer_url,
            "client",
            "subject",
        )
        .await?;
        assert!(meta.application_grant.is_some());
        state
            .tokens
            .store
            .store_issued_grant_async(access, None, meta)
            .await?;
        request(&state, &token, StatusCode::OK, "success", None).await?;
        sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE environment_id=$1")
            .bind(env.environment_id)
            .execute(&pool)
            .await?;
        request(
            &state,
            &token,
            StatusCode::UNAUTHORIZED,
            "application_authorization_changed",
            Some("invalid_token"),
        )
        .await?;
        sqlx::query("UPDATE aegaeon.end_users SET status='ACTIVE' WHERE environment_id=$1")
            .bind(env.environment_id)
            .execute(&pool)
            .await?;
        request(&state, &token, StatusCode::OK, "success", None).await?;
        let closed = sqlx::postgres::PgPoolOptions::new()
            .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
            .await?;
        closed.close().await;
        let mut unavailable = state.clone();
        unavailable.application_authority = Some(Authority {
            projections: closed,
            memberships: None,
        });
        request(
            &unavailable,
            &token,
            StatusCode::SERVICE_UNAVAILABLE,
            "application_authority_unavailable",
            Some("temporarily_unavailable"),
        )
        .await?;
        request(&state, &token, StatusCode::OK, "success", None).await?;
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
