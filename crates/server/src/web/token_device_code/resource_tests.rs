//! Device token handlers use real polling, minting, storage and database audit.
use super::*;
use crate::web::test_support::{
    cleanup_test_environment, finish_test, sample_registered_client, setup_test_environment,
    test_app_state, test_pg_pool, TestEnvironment, TestResult,
};
use axum::body::to_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use std::sync::Arc;

const CLIENT: &str = "device-resource-client";
const SUBJECT: &str = "device-resource-user";
const TARGET: &str = "https://resource.example/api";

fn oidc(issuer: &str) -> TestResult<crate::oidc::OidcConfig> {
    Ok(crate::oidc::OidcConfig {
        issuer: issuer.into(),
        id_token_ttl_secs: 300,
        discovery_enabled: true,
        userinfo_enabled: true,
        logout_enabled: false,
        backchannel_logout_enabled: false,
        logout_session_ttl_secs: 600,
        backchannel_logout_timeout_secs: 2,
        require_nonce: false,
        signing_key: crate::oidc::OidcSigningKey::from_rsa_pem(
            "device-resource-default".into(),
            include_str!("../../../tests/fixtures/rsa2048-private.pk8.pem"),
        )?,
        request_object_encryption_key: None,
    })
}

fn configure_issuer(state: &mut AppState, jwt: bool, configured_oidc: bool) -> TestResult {
    let oidc = configured_oidc.then(|| oidc(&state.issuer)).transpose()?;
    state.oidc.config = oidc.clone().map(Arc::new);
    state.tokens.issuer = Arc::new(
        crate::authcode::TokenIssuer::with_stores(
            Arc::clone(&state.keys.access_token),
            state.tokens.issuer.code_store.clone(),
            state.tokens.store.as_ref().clone(),
        )
        .with_issuer(state.issuer.to_string())
        .with_jwt_access_tokens_enabled(jwt)
        .with_oidc(oidc),
    );
    Ok(())
}

async fn fixture(pool: sqlx::PgPool, env: &TestEnvironment, redis: bool) -> TestResult<AppState> {
    let mut state = test_app_state(pool, env).await?;
    Arc::make_mut(&mut state.cfg).enable_device_authz = true;
    for client_id in [CLIENT, TARGET] {
        let mut client = sample_registered_client(client_id);
        client.allowed_grant_types = vec![DEVICE_CODE_GRANT_TYPE.into()];
        client.allowed_scopes = vec!["read".into(), "openid".into(), "profile".into()];
        assert!(state.clients.try_register(client)?);
    }
    state.keys.access_token = Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?);
    state.device.code_store = Arc::new(
        if redis {
            crate::device_authz::DeviceCodeStore::try_from_shared_store_env_with_policy(
                60,
                5,
                &crate::config::RuntimeStateNamespace::for_tests(format!(
                    "device-http-resource-{}",
                    uuid::Uuid::new_v4()
                )),
            )?
        } else {
            crate::device_authz::DeviceCodeStore::new_process_local_for_tests()
        }
        .with_poll_interval_for_tests(0),
    );
    configure_issuer(&mut state, true, false)?;
    Ok(state)
}

async fn grant(
    state: &AppState,
    client: &str,
    scope: Option<&str>,
    resource: Option<&str>,
) -> TestResult<crate::device_authz::DeviceAuthorizationResponse> {
    let grant = state
        .device
        .code_store
        .try_create_with_resource_async(
            client.into(),
            scope.map(str::to_owned),
            resource.map(str::to_owned),
            None,
            format!("{}/device", state.issuer),
        )
        .await
        .ok_or("device authorization allocation failed")?;
    assert!(
        state
            .device
            .code_store
            .try_approve_async(grant.user_code.clone(), SUBJECT.into())
            .await?
    );
    Ok(grant)
}

async fn poll(
    state: &AppState,
    grant: &crate::device_authz::DeviceAuthorizationResponse,
    client: &str,
    resource: Option<&str>,
) -> TestResult<(StatusCode, Value)> {
    let mut params = vec![
        ("grant_type".into(), DEVICE_CODE_GRANT_TYPE.into()),
        ("client_id".into(), client.into()),
        ("device_code".into(), grant.device_code.clone()),
    ];
    if let Some(resource) = resource {
        params.push(("resource".into(), resource.into()));
    }
    let form = super::super::token_form::token_form_from_params(&params, state.issuer.as_str())
        .map_err(|_| "device token form rejected")?;
    let ctx = TokenEndpointContext {
        request_id: uuid::Uuid::new_v4().to_string(),
        params,
        form,
        grant_type: DEVICE_CODE_GRANT_TYPE.into(),
        client_id: client.into(),
        resource: resource.map(str::to_owned),
        sender_constraint: crate::policy::SenderConstraint::None,
        enforce_refresh_sender_binding: true,
        authorization_code_grant_allowed: false,
        refresh_grant_allowed: false,
        cnf_for_at: None,
        sender_binding: None,
        issuer_req: serde_json::from_value(json!({
            "grant_type": DEVICE_CODE_GRANT_TYPE, "client_id": client, "resource": resource
        }))?,
    };
    let response = handle_token_device_code_grant(state, &ctx).await;
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    Ok((status, body))
}

fn reject(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_target");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("id_token").is_none());
}

fn accepted(
    state: &AppState,
    status: StatusCode,
    body: &Value,
    jwt: bool,
    audience: &str,
) -> TestResult {
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"]
        .as_str()
        .ok_or("access token missing")?;
    if jwt {
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(token.split('.').nth(1).ok_or("JWT payload missing")?)?,
        )?;
        assert_eq!(claims["aud"], audience);
        assert_eq!(claims["sub"], SUBJECT);
    } else {
        assert!(!token.contains('.'));
    }
    let meta = state
        .tokens
        .store
        .try_get_bearer_meta(token)?
        .ok_or("saved metadata missing")?;
    assert_eq!(meta.audience, audience);
    assert_eq!(meta.user_id, SUBJECT);
    Ok(())
}

async fn scenarios(redis: bool) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(pool.clone(), &env, redis).await?;
        for (configured_oidc, scope) in
            [(false, None), (false, Some("openid")), (true, Some("read"))]
        {
            configure_issuer(&mut state, true, configured_oidc)?;
            let code = grant(&state, CLIENT, scope, None).await?;
            let count = state.device.code_store.try_active_count()?;
            let (status, body) = poll(&state, &code, CLIENT, None).await?;
            reject(status, &body);
            assert_eq!(state.device.code_store.try_active_count()?, count);
            configure_issuer(&mut state, false, false)?;
            let (status, body) = poll(&state, &code, CLIENT, None).await?;
            accepted(&state, status, &body, false, CLIENT)?;
            let (status, body) = poll(&state, &code, CLIENT, None).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"], "expired_token");
        }
        configure_issuer(&mut state, true, false)?;
        for client in [CLIENT, TARGET] {
            for requested in [None, Some(TARGET)] {
                let code = grant(&state, client, Some("read"), Some(TARGET)).await?;
                let (status, body) = poll(
                    &state,
                    &code,
                    client,
                    Some("https://resource.example/other"),
                )
                .await?;
                reject(status, &body);
                let (status, body) = poll(&state, &code, client, requested).await?;
                accepted(&state, status, &body, true, TARGET)?;
            }
        }
        configure_issuer(&mut state, true, true)?;
        let userinfo = crate::resource_audience::userinfo(state.issuer.as_str());
        for scope in ["openid", "openid profile"] {
            let code = grant(&state, CLIENT, Some(scope), None).await?;
            let (status, body) = poll(&state, &code, CLIENT, None).await?;
            accepted(&state, status, &body, true, &userinfo)?;
        }
        for scope in [
            "OpenId",
            "openidish",
            "openid\tprofile",
            "openid  profile",
            "openid openid",
        ] {
            let code = grant(&state, CLIENT, Some(scope), None).await?;
            let count = state.device.code_store.try_active_count()?;
            let (status, body) = poll(&state, &code, CLIENT, None).await?;
            reject(status, &body);
            assert_eq!(state.device.code_store.try_active_count()?, count);
        }
        configure_issuer(&mut state, false, false)?;
        let code = grant(&state, CLIENT, Some("read"), None).await?;
        let (status, body) = poll(&state, &code, CLIENT, None).await?;
        accepted(&state, status, &body, false, CLIENT)
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL"]
async fn device_resource_http_memory_rejects_before_consumption_and_binds_jwt_audience(
) -> TestResult {
    scenarios(false).await
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL and Redis"]
async fn device_resource_http_redis_rejects_before_consumption_and_binds_jwt_audience() -> TestResult
{
    scenarios(true).await
}
