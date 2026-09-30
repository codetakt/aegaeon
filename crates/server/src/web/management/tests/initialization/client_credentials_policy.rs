use super::*;

async fn update_policy(
    app: &axum::Router,
    uri: &str,
    session: &str,
    value: serde_json::Value,
    expected: StatusCode,
) -> ManagementTestResult {
    let mut patch = request(uri, value, session, "https://admin.aegaeon.test", true);
    *patch.method_mut() = Method::PATCH;
    let response = app.clone().oneshot(patch).await?;
    let status = response.status();
    let bytes = body::to_bytes(response.into_body(), 65536).await?;
    assert_eq!(status, expected, "{}", String::from_utf8_lossy(&bytes));
    Ok(())
}

pub(super) async fn management_session(
    pool: &PgPool,
) -> Result<(axum::Router, String), Box<dyn std::error::Error>> {
    let mut management = test_management_state();
    management.cfg = std::sync::Arc::new(
        super::super::super::ManagementConfig::try_from_env_with_database(&pool).await?,
    );
    let app = crate::web::build_router(test_app_state(pool.clone(), management)?);
    let response = app
        .clone()
        .oneshot(request(
            "/api/v1/authentication/sessions",
            serde_json::json!({"email":input().owner_email,"password":input().owner_password}),
            "",
            "https://admin.aegaeon.test",
            true,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let session = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("aegaeon_admin_session="))
        .expect("management session")
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    Ok((app, session))
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_client_credentials_policy_activates_and_preserves_separate_exchange_catalog(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult =
        async {
            let initialized = initialize_management(&pool, &input()).await?;
            let initial = crate::runtime_configuration::load_database_runtime_configuration(
                &pool,
                &initialized.issuer_host,
            )
            .await?;
            assert_eq!(initial.state.policy.client_credentials, Default::default());
            let (app, session) = management_session(&pool).await?;
            let catalog = serde_json::json!({"version":1,"targets":[{
            "audience":"orders-api","resourceAliases":["https://orders.example/api"]}],"rules":[]});
            let authority = serde_json::json!({"version":1,"resourceServers":[{
            "targetAudience":"orders-api","introspectionClients":["resource-server"]}],
            "rules":[{"clientId":"worker","targetAudience":"orders-api","scopes":["orders.read"],
                "defaultScopes":["orders.read"],"defaultTarget":true}]});
            let uri = format!(
                "/api/v1/teams/{}/environments/{}/policies",
                initialized.team_id, initialized.environment_id
            );
            update_policy(
                &app,
                &uri,
                &session,
                serde_json::json!({
                    "baseConfigurationVersionId": initial.active_configuration_version_id,
                    "tokenExchange": catalog, "clientCredentials": authority,
                    "allowSecurityDowngrade":true,"reason":"configure client credentials authority"
                }),
                StatusCode::OK,
            )
            .await?;
            let loaded = crate::runtime_configuration::load_database_runtime_configuration(
                &pool,
                &initialized.issuer_host,
            )
            .await?;
            assert_ne!(
                loaded.active_configuration_version_id,
                initial.active_configuration_version_id
            );
            assert_eq!(
                serde_json::to_value(&loaded.state.policy.client_credentials)?,
                authority
            );
            assert_eq!(
                serde_json::to_value(&loaded.state.policy.token_exchange)?,
                catalog
            );
            let config = crate::config::ServerConfig::default()
                .with_management_policy(&loaded.state.policy)?;
            assert_eq!(
                config.client_credentials,
                loaded.state.policy.client_credentials
            );
            let configured = snapshot(&pool, initialized.environment_id).await?;
            let empty = serde_json::json!({"version":1,"resourceServers":[],"rules":[]});
            for (allowed, reason) in [(false, "remove authority"), (true, "  ")] {
                update_policy(
                    &app,
                    &uri,
                    &session,
                    serde_json::json!({
                        "baseConfigurationVersionId": loaded.active_configuration_version_id,
                        "clientCredentials":empty,"allowSecurityDowngrade":allowed,"reason":reason
                    }),
                    StatusCode::CONFLICT,
                )
                .await?;
                assert_eq!(
                    snapshot(&pool, initialized.environment_id).await?,
                    configured
                );
            }
            let mut invalid = authority.clone();
            invalid["rules"][0]["defaultScopes"] = serde_json::json!(["unregistered.scope"]);
            update_policy(&app, &uri, &session, serde_json::json!({
            "baseConfigurationVersionId":loaded.active_configuration_version_id,
            "clientCredentials":invalid,"allowSecurityDowngrade":true,"reason":"invalid defaults"
        }), StatusCode::BAD_REQUEST).await?;
            assert_eq!(
                snapshot(&pool, initialized.environment_id).await?,
                configured
            );
            update_policy(&app, &uri, &session, serde_json::json!({
            "baseConfigurationVersionId":loaded.active_configuration_version_id,
            "clientCredentials":empty,"allowSecurityDowngrade":true,"reason":"remove authority"
        }), StatusCode::OK).await?;
            let cleared = crate::runtime_configuration::load_database_runtime_configuration(
                &pool,
                &initialized.issuer_host,
            )
            .await?;
            assert_eq!(cleared.state.policy.client_credentials, Default::default());
            assert_eq!(
                serde_json::to_value(&cleared.state.policy.token_exchange)?,
                catalog
            );
            Ok(())
        }
        .await;
    finish(result, cleanup(control, pool, &name).await)
}
