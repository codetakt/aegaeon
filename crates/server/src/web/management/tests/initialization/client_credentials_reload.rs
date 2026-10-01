//! Real management activation, database policy reload and PostgreSQL/Redis HTTP composition.
//! Profiles and initial registrations are fixture preparation; policy transitions use PATCH.
use super::*;
use crate::web::{
    test_support::{TestEnvironment, TestResult},
    token_client_credentials::tests as cc,
    AppState,
};
use serde_json::{json, Value};

async fn issue(state: &AppState, selector: (&str, &str)) -> TestResult<String> {
    let (status, body) = cc::request(
        state,
        "/token",
        cc::CALLER,
        cc::SECRET,
        &[
            ("grant_type", "client_credentials"),
            selector,
            ("scope", "api.read"),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(body["access_token"]
        .as_str()
        .ok_or("access token missing")?
        .to_owned())
}

async fn visible(state: &AppState, token: &str) -> TestResult<bool> {
    let (status, body) = cc::request(
        state,
        "/introspect",
        cc::RS,
        cc::RS_SECRET,
        &[("token", token)],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(body["active"].as_bool().ok_or("active Boolean missing")?)
}

async fn exercise(pool: &PgPool) -> ManagementTestResult {
    let initialized = initialize_management(pool, &input()).await?;
    let env = TestEnvironment {
        team_id: initialized.team_id,
        tenant_id: initialized.tenant_id,
        environment_id: initialized.environment_id,
        issuer_url: format!("https://{}", initialized.issuer_host),
        issuer_host: initialized.issuer_host,
    };
    // Initial profile only; no membership repair after the actual policy activations.
    sqlx::query("INSERT INTO aegaeon.oauth_profiles (environment_id, configuration_version_id, name, profile_type, is_default, require_pkce, require_state_parameter, require_iss_parameter, sender_constrained, enforce_refresh_sender_binding, allowed_grant_types, token_endpoint_auth_methods_allowed) VALUES ($1,$2,'client-credentials-fixture','DOWNSTREAM',true,true,true,true,'NONE',true,ARRAY['client_credentials'],ARRAY['client_secret_basic'])")
        .bind(env.environment_id).bind(initialized.configuration_version_id).execute(pool).await?;
    let seeded = cc::fixture(pool, &env, false, true).await?;
    let original = serde_json::to_value(&seeded.cfg.client_credentials)?;
    let (management, session) = super::client_credentials_policy::management_session(pool).await?;
    let empty = json!({"version":1,"resourceServers":[],"rules":[]});
    super::exchange_reload::patch(
        &management,
        pool,
        &env,
        &session,
        json!({"clientCredentials":empty}),
    )
    .await?;
    let denied = cc::reload(&seeded, &env).await?;
    let (status, body) = cc::request(
        &denied,
        "/token",
        cc::CALLER,
        cc::SECRET,
        &[
            ("grant_type", "client_credentials"),
            ("audience", cc::TARGET),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_target");
    let enabled = super::exchange_reload::patch(
        &management,
        pool,
        &env,
        &session,
        json!({"clientCredentials":original}),
    )
    .await?;
    let active = cc::reload(&denied, &env).await?;
    assert_eq!(
        active.cfg.client_credentials,
        enabled.state.policy.client_credentials
    );
    let token = issue(&active, ("resource", cc::ALIAS)).await?;
    assert!(visible(&active, &token).await?);
    let metadata = active
        .tokens
        .store
        .try_get_bearer_meta(&token)?
        .ok_or("metadata missing")?;
    assert_eq!(
        metadata
            .client_credentials_grant
            .as_ref()
            .ok_or("grant missing")?
            .configuration_version_id,
        enabled.active_configuration_version_id
    );
    super::exchange_reload::patch(
        &management,
        pool,
        &env,
        &session,
        json!({"authorizationCodeTimeToLiveSeconds":121}),
    )
    .await?;
    let (status, _) = cc::request(
        &active,
        "/introspect",
        cc::RS,
        cc::RS_SECRET,
        &[("token", &token)],
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "stale runtime refuses new admissions"
    );
    let preserved = cc::reload(&active, &env).await?;
    assert!(
        visible(&preserved, &token).await?,
        "unrelated activation preserves selected authority"
    );
    let mut changed: Value = original;
    changed["rules"][0]["defaultScopes"] = json!(["api.write"]);
    super::exchange_reload::patch(
        &management,
        pool,
        &env,
        &session,
        json!({"clientCredentials":changed}),
    )
    .await?;
    let changed = cc::reload(&preserved, &env).await?;
    assert!(
        !visible(&changed, &token).await?,
        "selected authority change invalidates old token"
    );
    let fresh = issue(&changed, ("audience", cc::TARGET)).await?;
    assert!(visible(&changed, &fresh).await?);
    let stored = changed
        .tokens
        .store
        .try_get_bearer_meta(&token)?
        .ok_or("retained old metadata missing")?;
    assert_eq!(
        stored.client_credentials_grant, metadata.client_credentials_grant,
        "activation must not backfill captured Redis authority"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB and private Redis; uses a disposable database"]
async fn shared_redis_pg_client_credentials_management_activation_controls_online_authority(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result = exercise(&pool).await;
    finish(result, cleanup(control, pool, &name).await)
}
