use super::*;
use crate::web::test_support;

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn upstream_logout_relay_query_preserves_vendor_fields_and_rejects_before_records(
) -> test_support::TestResult {
    let pool = test_support::test_pg_pool()
        .await?
        .ok_or("Postgres fixture required")?;
    let env = test_support::setup_test_environment(&pool).await?;
    let result = relay_scenario(&pool, &env).await;
    sqlx::query(
        "DELETE FROM aegaeon.federation_logout_recovery_incidents WHERE environment_id = $1",
    )
    .bind(env.environment_id)
    .execute(&pool)
    .await?;
    test_support::finish_test(
        result,
        test_support::cleanup_test_environment(&pool, &env).await,
    )
}

async fn relay_scenario(
    pool: &sqlx::PgPool,
    env: &test_support::TestEnvironment,
) -> test_support::TestResult {
    let state = test_support::test_app_state(pool.clone(), env).await?;
    let callback = build_upstream_logout_callback_uri(state.base_url.as_str());
    let encoded_callback: String =
        url::form_urlencoded::byte_serialize(callback.as_bytes()).collect();
    let prefix=format!("vendor=%2f&vendor=two+words&blank=&post_logout_redirect_uri={encoded_callback}&logout%5Fhint=hint");
    let mut session = UpstreamLogoutSession {
        issuer: "https://issuer.example".into(),
        end_session_endpoint: Some(format!("https://issuer.example/logout?{prefix}")),
        back_channel: false,
        session_hint_claim: Some("sid".into()),
        session_hint_value: Some("hint".into()),
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
        team_id: Some(env.team_id),
        tenant_id: Some(env.tenant_id),
        environment_id: Some(env.environment_id),
        connection_id: None,
    };
    let target = build_upstream_logout_redirect_target_with_relay(
        &state,
        &session,
        None,
        "https://client.example/complete",
        Some("downstream-state"),
        None,
        "query-test",
    )
    .await
    .map_err(|e| format!("relay {}", e.status()))?
    .ok_or("target")?;
    let url = Url::parse(&target)?;
    assert!(url.query().ok_or("query")?.starts_with(&prefix));
    for name in ["state", "post_logout_redirect_uri", "logout_hint"] {
        assert_eq!(url.query_pairs().filter(|(key, _)| key == name).count(), 1);
    }
    let relay_token = url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .ok_or("state")?
        .1
        .into_owned();
    let relay = state
        .upstream
        .logout_relay_store
        .try_take(&relay_token)?
        .ok_or("stored relay")?;
    assert_eq!(
        relay.downstream_redirect_uri,
        "https://client.example/complete"
    );
    assert_eq!(relay.downstream_state.as_deref(), Some("downstream-state"));
    assert!(relay.incident_id.is_some());
    for query in [
        "state=attacker",
        "st%61te=attacker",
        "post_logout_redirect_uri=https%3A%2F%2Fevil.example",
        "logout_hint=hint&logout%5Fhint=hint",
        "logout_hint=%FF",
    ] {
        session.end_session_endpoint = Some(format!("https://issuer.example/logout?{query}"));
        assert!(build_upstream_logout_redirect_target_with_relay(
            &state,
            &session,
            None,
            "https://client.example/complete",
            None,
            None,
            "rejected-query-test"
        )
        .await
        .map_err(|e| format!("relay {}", e.status()))?
        .is_none());
        assert!(state
            .upstream
            .logout_relay_store
            .try_take("attacker")?
            .is_none());
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.federation_logout_recovery_incidents WHERE environment_id=$1",
    )
    .bind(env.environment_id)
    .fetch_one(pool)
    .await?;
    assert_eq!(count, 1, "query rejection must precede incident creation");
    Ok(())
}
