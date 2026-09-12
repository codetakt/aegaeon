use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_initialization_roundtrips_exchange_policy_without_repair_sql() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let initial = crate::runtime_configuration::load_database_runtime_configuration(
            &pool, &initialized.issuer_host).await?;
        let empty = serde_json::json!({"version":1,"targets":[],"rules":[]});
        assert_eq!(serde_json::to_value(&initial.state.policy)?["tokenExchange"], empty);
        let mut management = test_management_state();
        management.cfg = std::sync::Arc::new(
            super::super::super::ManagementConfig::try_from_env_with_database(&pool).await?);
        let app = crate::web::build_router(test_app_state(pool.clone(), management)?);
        let login = serde_json::json!({"email":input().owner_email,"password":input().owner_password});
        let response = app.clone().oneshot(request("/api/v1/authentication/sessions",
            login, "", "https://admin.aegaeon.test", true)).await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let session = response.headers().get_all("set-cookie").iter().filter_map(|v|v.to_str().ok())
            .find(|v|v.starts_with("aegaeon_admin_session=")).expect("management session")
            .split(';').next().unwrap().to_owned();
        let target = serde_json::json!({"version":1,"targets":[{
            "audience":"internal-api","resourceAliases":["https://api.example.test/resource"]}],"rules":[]});
        let uri = format!("/api/v1/teams/{}/environments/{}/policies",
            initialized.team_id, initialized.environment_id);
        let mut patch = request(&uri, serde_json::json!({
            "baseConfigurationVersionId":initial.active_configuration_version_id,
            "tokenExchange":target,"reason":"integration policy regression"
        }), &session, "https://admin.aegaeon.test", true);
        *patch.method_mut() = Method::PATCH;
        let response = app.clone().oneshot(patch).await?;
        let status = response.status();
        let bytes = body::to_bytes(response.into_body(), 65536).await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&bytes));
        let reloaded = crate::runtime_configuration::load_database_runtime_configuration(
            &pool, &initialized.issuer_host).await?;
        assert_ne!(reloaded.active_configuration_version_id, initial.active_configuration_version_id);
        assert_eq!(serde_json::to_value(&reloaded.state.policy)?["tokenExchange"], target);
        let first_snapshot = snapshot(&pool, initialized.environment_id).await?;
        let uri = format!("/api/v1/teams/{}/tenants/{}/environments",
            initialized.team_id, initialized.tenant_id);
        let response = app.oneshot(request(&uri, serde_json::json!({"name":"Second","slug":"second"}),
            &session, "https://admin.aegaeon.test", true)).await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let second: serde_json::Value = serde_json::from_slice(
            &body::to_bytes(response.into_body(), 65536).await?)?;
        let second_host = second["issuerHost"].as_str().expect("second issuer host");
        assert_ne!(second_host, initialized.issuer_host);
        let second_runtime = crate::runtime_configuration::load_database_runtime_configuration(
            &pool, second_host).await?;
        assert_eq!(serde_json::to_value(&second_runtime.state.policy)?["tokenExchange"], empty);
        assert_eq!(snapshot(&pool, initialized.environment_id).await?, first_snapshot);
        Ok(())
    }.await;
    cleanup(control, pool, &name).await?;
    result
}
