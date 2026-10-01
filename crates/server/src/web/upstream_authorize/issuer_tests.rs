use super::context::load_upstream_authorize_context;
use super::flow::{build_upstream_authorize_redirect_response, store_upstream_authorize_request};
use super::UpstreamAuthorizeInput;
use crate::web::upstream_callback_connection::validate_and_hydrate_upstream_callback_connection;
use crate::web::upstream_callback_state::{
    consume_upstream_callback_context, validate_upstream_callback_issuer, UpstreamCallbackQuery,
};
use crate::web::upstream_metadata::validate_upstream_discovery;
use crate::web::{test_support, upstream_tests};
use axum::http::{header, HeaderMap};

#[path = "issuer_router_tests.rs"]
mod router;

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn upstream_issuer_active_connection_preserves_identity_and_frozen_response_policy(
) -> test_support::TestResult {
    let pool = test_support::test_pg_pool()
        .await?
        .ok_or("Postgres fixture required")?;
    let env = test_support::setup_test_environment(&pool).await?;
    let result = active_issuer_scenario(&pool, &env).await;
    sqlx::query("DELETE FROM aegaeon.connections WHERE environment_id = $1")
        .bind(env.environment_id)
        .execute(&pool)
        .await?;
    test_support::finish_test(
        result,
        test_support::cleanup_test_environment(&pool, &env).await,
    )
}

async fn active_issuer_scenario(
    pool: &sqlx::PgPool,
    env: &test_support::TestEnvironment,
) -> test_support::TestResult {
    let state = test_support::test_app_state(pool.clone(), env).await?;
    let version: uuid::Uuid = sqlx::query_scalar(
        "SELECT active_configuration_version_id FROM aegaeon.environments WHERE id = $1",
    )
    .bind(env.environment_id)
    .fetch_one(pool)
    .await?;
    sqlx::query("INSERT INTO aegaeon.oauth_profiles (environment_id, configuration_version_id, name, profile_type, is_default, require_pkce, require_state_parameter, require_iss_parameter, sender_constrained, enforce_refresh_sender_binding, allowed_grant_types, token_endpoint_auth_methods_allowed) VALUES ($1, $2, 'upstream-test', 'UPSTREAM', true, true, true, true, 'NONE', false, ARRAY['authorization_code'], ARRAY['none'])")
        .bind(env.environment_id).bind(version).execute(pool).await?;
    for (index, issuer) in ["https://issuer.example", "https://issuer.example/"]
        .into_iter()
        .enumerate()
    {
        let identifier = format!("issuer-{index}");
        sqlx::query("INSERT INTO aegaeon.connections (environment_id, configuration_version_id, connection_identifier, name, connection_type, issuer_url, client_id, client_auth_method, status) VALUES ($1, $2, $3, $3, 'OIDC', $4, 'client', 'none', 'ACTIVE')")
            .bind(env.environment_id).bind(version).bind(&identifier).bind(issuer).execute(pool).await?;
        let mut context =
            load_upstream_authorize_context(&state, pool, &env.issuer_url, &identifier)
                .await
                .map_err(|e| format!("context: {}", e.status()))?;
        assert_eq!(context.issuer, issuer);
        for required in [false, true] {
            context.profile.require_iss_parameter = required;
            for advertised in [None, Some(false), Some(true)] {
                let mut discovery = upstream_tests::base_discovery(issuer)?;
                discovery.authorization_response_iss_parameter_supported = advertised;
                let admissible =
                    validate_upstream_discovery(&discovery, issuer, &context.profile, "none", &[]);
                if required && advertised != Some(true) {
                    assert!(admissible.is_err());
                    continue;
                }
                admissible?;
                let input = UpstreamAuthorizeInput {
                    return_to: Some("/continue".into()),
                    scopes: vec!["openid".into()],
                    scope: "openid".into(),
                    acr: None,
                    max_age: None,
                };
                let flow = store_upstream_authorize_request(
                    &state,
                    &identifier,
                    &input,
                    &context,
                    &discovery,
                    &env.issuer_url,
                )
                .await
                .map_err(|e| format!("store: {}", e.status()))?;
                let response = build_upstream_authorize_redirect_response(
                    &env.issuer_url,
                    &discovery,
                    "client",
                    &input,
                    &flow,
                    false,
                )
                .map_err(|e| format!("redirect: {}", e.status()))?;
                let url = url::Url::parse(response.headers()[header::LOCATION].to_str()?)?;
                let query: std::collections::HashMap<_, _> =
                    url.query_pairs().into_owned().collect();
                let cookie = response.headers()[header::SET_COOKIE]
                    .to_str()?
                    .split(';')
                    .next()
                    .ok_or("cookie")?;
                let mut headers = HeaderMap::new();
                headers.insert(header::COOKIE, cookie.parse()?);
                let params: UpstreamCallbackQuery = serde_json::from_value(
                    serde_json::json!({"state": query["state"], "code": "code", "iss": issuer}),
                )?;
                let mut callback = consume_upstream_callback_context(
                    &state,
                    &params,
                    &headers,
                    &identifier,
                    &env.issuer_url,
                )
                .await
                .map_err(|e| format!("consume: {}", e.status()))?;
                assert_eq!(callback.request.issuer, issuer);
                assert_eq!(
                    callback.request.require_iss_parameter,
                    required || advertised == Some(true)
                );
                assert_eq!(callback.code.as_deref(), Some("code"));
                validate_upstream_callback_issuer(&params, &callback.request, &env.issuer_url)
                    .map_err(|e| format!("issuer: {}", e.status()))?;
                validate_and_hydrate_upstream_callback_connection(
                    pool,
                    &mut callback.request,
                    &identifier,
                    &env.issuer_url,
                )
                .await
                .map_err(|e| format!("active currentness: {}", e.status()))?;
                upstream_tests::issuer_identity::check_upstream_issuer_signed_token(
                    &callback.request,
                    &discovery,
                )?;
                router::check_callbacks(&state, &identifier, &callback.request).await?;
                // Later metadata cannot lower the requirement already frozen in the transaction.
                discovery.authorization_response_iss_parameter_supported = None;
                for error in [false, true] {
                    for claim in [None, Some(issuer), Some("https://other.example")] {
                        let params: UpstreamCallbackQuery = serde_json::from_value(
                            serde_json::json!({"iss": claim, "error": if error {Some("access_denied")} else {None}, "code": if error {None} else {Some("code")}}),
                        )?;
                        assert_eq!(
                            validate_upstream_callback_issuer(
                                &params,
                                &callback.request,
                                &env.issuer_url
                            )
                            .is_ok(),
                            claim == Some(issuer)
                                || (claim.is_none() && !callback.request.require_iss_parameter)
                        );
                    }
                }
                let mut stale = callback.request.clone();
                stale.issuer = if issuer.ends_with('/') {
                    issuer.trim_end_matches('/').into()
                } else {
                    format!("{issuer}/")
                };
                assert!(validate_and_hydrate_upstream_callback_connection(
                    pool,
                    &mut stale,
                    &identifier,
                    &env.issuer_url
                )
                .await
                .is_err());
            }
        }
    }
    Ok(())
}
