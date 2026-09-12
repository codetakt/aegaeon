//! Real management PATCH, database reload and /token composition. The initial
//! profile is a SQL fixture, the client uses DCR persistence, and codes use the
//! production issuer. Browser consent and process restart remain E2E obligations.
use super::*;
use crate::web::{test_support::TestEnvironment, token_exchange::tests as exchange};
use serde_json::{json, Value};
use std::sync::Arc;

async fn patch(
    app: &Router,
    pool: &PgPool,
    env: &TestEnvironment,
    session: &str,
    mut changes: Value,
) -> Result<crate::runtime_configuration::DatabaseRuntimeConfiguration, Box<dyn std::error::Error>>
{
    let before =
        crate::runtime_configuration::load_database_runtime_configuration(pool, &env.issuer_host)
            .await?;
    changes["baseConfigurationVersionId"] = json!(before.active_configuration_version_id);
    changes["reason"] = json!("exchange configuration composition regression");
    changes["allowSecurityDowngrade"] = json!(true);
    let uri = format!(
        "/api/v1/teams/{}/environments/{}/policies",
        env.team_id, env.environment_id
    );
    let mut req = request(&uri, changes, session, "https://admin.aegaeon.test", true);
    *req.method_mut() = Method::PATCH;
    let response = app.clone().oneshot(req).await?;
    let status = response.status();
    let bytes = body::to_bytes(response.into_body(), 65536).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let after =
        crate::runtime_configuration::load_database_runtime_configuration(pool, &env.issuer_host)
            .await?;
    assert_ne!(
        before.active_configuration_version_id,
        after.active_configuration_version_id
    );
    Ok(after)
}

async fn reload(
    pool: &PgPool,
    env: &TestEnvironment,
    previous: &crate::web::AppState,
) -> Result<crate::web::AppState, Box<dyn std::error::Error>> {
    let loaded =
        crate::runtime_configuration::load_database_runtime_configuration(pool, &env.issuer_host)
            .await?;
    let mut state = crate::web::test_support::test_app_state(pool.clone(), env).await?;
    let cfg = Arc::make_mut(&mut state.cfg);
    cfg.apply_management_policy(&loaded.state.policy)?;
    state.keys.access_token = Arc::clone(&previous.keys.access_token);
    state.tokens.store = Arc::clone(&previous.tokens.store);
    state.tokens.issuer = Arc::new(
        crate::authcode::TokenIssuer::with_stores(
            Arc::clone(&state.keys.access_token),
            previous.tokens.issuer.code_store.clone(),
            state.tokens.store.as_ref().clone(),
        )
        .with_issuer(env.issuer_url.clone())
        .with_token_exchange_policy(cfg.token_exchange.clone())
        .with_jwt_access_tokens_enabled(cfg.enable_jwt_access_tokens),
    );
    state.tokens.validator = Arc::new(
        crate::authcode::TokenValidator::with_policy(
            state.tokens.store.as_ref().clone(),
            Arc::clone(&state.keys.access_token),
            cfg.security_policy,
        )
        .with_issuer(Some(env.issuer_url.clone()))
        .with_jwt_access_tokens_enabled(cfg.enable_jwt_access_tokens),
    );
    Ok(state)
}

#[derive(Clone, Copy)]
enum Schedule {
    UnchangedExchangePolicy,
    ChangedExchangePolicy,
    EnableExchangePolicy,
    OtherEnvironment,
}

async fn scenario(schedule: Schedule, redis: bool) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let env = TestEnvironment {
            team_id: initialized.team_id,
            tenant_id: initialized.tenant_id,
            environment_id: initialized.environment_id,
            issuer_url: format!("https://{}", initialized.issuer_host),
            issuer_host: initialized.issuer_host,
        };
        // Initial test data only: no membership repair after activation.
        sqlx::query("INSERT INTO aegaeon.oauth_profiles (environment_id, configuration_version_id, name, profile_type, is_default, require_pkce, require_state_parameter, require_iss_parameter, sender_constrained, enforce_refresh_sender_binding, allowed_grant_types, token_endpoint_auth_methods_allowed) VALUES ($1,$2,'exchange-fixture','DOWNSTREAM',true,true,true,true,'NONE',true,ARRAY['authorization_code'],ARRAY['none'])")
            .bind(env.environment_id).bind(initialized.configuration_version_id).execute(&pool).await?;
        let mut management = test_management_state();
        management.cfg = Arc::new(super::super::super::ManagementConfig::try_from_env_with_database(&pool).await?);
        let app = crate::web::build_router(test_app_state(pool.clone(), management)?);
        let response = app.clone().oneshot(request("/api/v1/authentication/sessions",
            json!({"email": input().owner_email, "password": input().owner_password}),
            "", "https://admin.aegaeon.test", true)).await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let session = response.headers().get_all("set-cookie").iter().filter_map(|v|v.to_str().ok())
            .find(|v|v.starts_with("aegaeon_admin_session=")).expect("management session")
            .split(';').next().unwrap().to_owned();
        let configured = serde_json::to_value(exchange::policy(&env.issuer_url)?)?;
        let empty = json!({"version":1,"targets":[],"rules":[]});
        let initial_policy = if matches!(schedule, Schedule::EnableExchangePolicy) { empty } else { configured.clone() };
        patch(&app, &pool, &env, &session, json!({
            "tokenExchange": initial_policy, "senderConstraint":"none", "jwtAccessTokensEnabled":true,
            "retainRefreshChain":true,
            "allowedGrantTypes":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:token-exchange"]
        })).await?;
        let mut seeded = exchange::fixture(&pool, &env).await?;
        if redis { exchange::use_redis(&mut seeded)?; }
        let before = reload(&pool, &env, &seeded).await?;
        let original = exchange::grant(&before).await?;
        let source = original["access_token"].as_str().ok_or("source token")?;
        let refresh = original["refresh_token"].as_str().ok_or("refresh token")?;
        let old_meta = before.tokens.store.try_get_bearer_meta(source)?.ok_or("source metadata")?;
        let old_parent = before.tokens.store.try_get_refresh_token(refresh)?.ok_or("refresh metadata")?;
        assert_eq!(old_meta.exchange_grant.is_some(), !matches!(schedule, Schedule::EnableExchangePolicy));
        match schedule {
            Schedule::OtherEnvironment => {
                isolation::change_other_environment(&app, &pool, &env, &session, &before, source, redis).await?;
            }
            Schedule::UnchangedExchangePolicy => {
                patch(&app, &pool, &env, &session, json!({"authorizationCodeTimeToLiveSeconds":121})).await?;
            }
            Schedule::ChangedExchangePolicy => {
                let mut changed = configured.clone();
                changed["rules"][0]["defaultScopes"] = json!(["api.write"]);
                patch(&app, &pool, &env, &session, json!({"tokenExchange":changed})).await?;
            }
            Schedule::EnableExchangePolicy => {
                patch(&app, &pool, &env, &session, json!({"tokenExchange":configured})).await?;
            }
        }
        let after = reload(&pool, &env, &before).await?;
        assert_eq!(after.tokens.store.try_get_bearer_meta(source)?.ok_or("source after reload")?.exchange_grant, old_meta.exchange_grant);
        let (status, body) = exchange::exchange(&after, source, &[("audience","internal-api")], true).await?;
        let allowed = matches!(schedule, Schedule::UnchangedExchangePolicy | Schedule::OtherEnvironment);
        assert_eq!(status, if allowed { StatusCode::OK } else { StatusCode::BAD_REQUEST }, "{body}");
        if !allowed { assert_eq!(body["error"], "invalid_target", "{body}"); }
        let (status, refreshed) = exchange::request(&after, &[("grant_type","refresh_token"),
            ("client_id","target-exchange-client"),("refresh_token",refresh)], true).await?;
        assert_eq!(status, StatusCode::OK, "refresh: {refreshed}");
        let next_parent = after.tokens.store.try_get_refresh_token(refreshed["refresh_token"].as_str().ok_or("rotated refresh")?)?.ok_or("rotated metadata")?;
        assert_eq!(next_parent.exchange_grant, old_parent.exchange_grant, "refresh must preserve original policy identity and root");
        assert_eq!(serde_json::to_value(&next_parent.target_context)?, serde_json::to_value(&old_parent.target_context)?);
        let refreshed_source = refreshed["access_token"].as_str().ok_or("refreshed access")?;
        assert_eq!(after.tokens.store.try_get_bearer_meta(refreshed_source)?.ok_or("refreshed metadata")?.exchange_grant, old_meta.exchange_grant);
        let (status, body) = exchange::exchange(&after, refreshed_source, &[("audience","internal-api")], true).await?;
        assert_eq!(status, if allowed { StatusCode::OK } else { StatusCode::BAD_REQUEST }, "refreshed exchange: {body}");
        if !allowed { assert_eq!(body["error"], "invalid_target", "{body}"); }
        // Fresh authorization captures the new policy in every schedule.
        let fresh = exchange::grant(&after).await?;
        let (status, body) = exchange::exchange(&after, fresh["access_token"].as_str().ok_or("fresh source")?, &[("audience","internal-api")], true).await?;
        assert_eq!(status, StatusCode::OK, "fresh authority: {body}");
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_exchange_reload_preserves_authority_for_unchanged_exchange_policy(
) -> ManagementTestResult {
    scenario(Schedule::UnchangedExchangePolicy, false).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_exchange_reload_rejects_changed_policy_and_preserves_refresh_snapshot(
) -> ManagementTestResult {
    scenario(Schedule::ChangedExchangePolicy, false).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_exchange_reload_never_backfills_authority_after_enablement() -> ManagementTestResult {
    scenario(Schedule::EnableExchangePolicy, false).await
}

mod isolation;

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB and private Redis"]
async fn shared_redis_pg_exchange_reload_preserves_authority_for_unchanged_policy(
) -> ManagementTestResult {
    scenario(Schedule::UnchangedExchangePolicy, true).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB and private Redis"]
async fn shared_redis_pg_exchange_reload_rejects_changed_policy() -> ManagementTestResult {
    scenario(Schedule::ChangedExchangePolicy, true).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB and private Redis"]
async fn shared_redis_pg_exchange_reload_never_backfills_authority() -> ManagementTestResult {
    scenario(Schedule::EnableExchangePolicy, true).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB and private Redis"]
async fn shared_redis_pg_exchange_reload_isolates_other_environment() -> ManagementTestResult {
    scenario(Schedule::OtherEnvironment, true).await
}
