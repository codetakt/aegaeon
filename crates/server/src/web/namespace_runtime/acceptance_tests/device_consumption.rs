use super::{
    browser_consumption::session,
    direct::grant,
    support::{
        durable_csrf_fixture as fixture, remote, unavailable, unavailable_states, TestResult,
    },
};
use crate::{
    device_authz::DevicePollResult,
    web::{self, test_support},
};
use axum::{
    body::to_bytes,
    extract::{OriginalUri, State},
    http::{header, HeaderMap, StatusCode},
    Form,
};
use serde_json::Value;
use std::sync::Arc;
const DEVICE: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_device_actions_keep_csrf_and_approval_before_matching_grant() -> TestResult {
    exercise(false).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime; SQL device approval and atomic grant"]
async fn pg_namespace_sql_device_actions_and_atomic_grant() -> TestResult {
    exercise(true).await
}

async fn exercise(postgres: bool) -> TestResult {
    for approve in [true, false] {
        let (mut state, _) = fixture().await?;
        Arc::make_mut(&mut state.cfg).enable_device_authz = true;
        if postgres {
            state.subject_namespace = None;
            let database = crate::authcode::store::PostgresGrantDatabase::new(
                state.db_pool.clone(),
                &crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id),
            );
            state.device.code_store = Arc::new(
                crate::device_authz::DeviceCodeStore::from_postgres(database.clone(), 60, 5)?,
            );
            let store = crate::authcode::store::TokenStore::from_postgres(database);
            Arc::get_mut(&mut state.tokens.issuer)
                .ok_or("test issuer must be uniquely owned")?
                .token_store = store.clone();
            let mut validator = state.tokens.validator.as_ref().clone();
            validator.replace_store_for_tests(store.clone());
            state.tokens.validator = Arc::new(validator);
            state.tokens.store = Arc::new(store);
        }
        state.validate_subject_namespace().await?;
        let mut client = test_support::sample_registered_client("namespace-client");
        client.allowed_grant_types.push(DEVICE.into());
        state.clients.register(client);
        let created = state
            .device
            .code_store
            .try_create_with_resource_async(
                "namespace-client".into(),
                Some("read".into()),
                None,
                None,
                "https://issuer.example/device".into(),
            )
            .await
            .ok_or("device request missing")?;
        let sid = session(&state, "namespace-user")?;
        let csrf = state.device.csrf_store.clone().try_generate_async().await?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={sid}; aegaeon_device_csrf={csrf}",
                web::AUTH_SESSION_COOKIE_NAME
            )
            .parse()?,
        );
        let mut form = vec![
            ("csrf_token".into(), csrf.clone()),
            ("user_code".into(), created.user_code.clone()),
        ];
        if approve {
            form.push(("confirm_device".into(), "yes".into()));
        }
        for denied in unavailable_states(&state) {
            let response = if approve {
                web::device_flow::device_approve(
                    State(denied.clone()),
                    remote(),
                    OriginalUri("/device/approve".parse()?),
                    headers.clone(),
                    Ok(Form(form.clone())),
                )
                .await
            } else {
                web::device_flow::device_deny(
                    State(denied.clone()),
                    remote(),
                    OriginalUri("/device/deny".parse()?),
                    headers.clone(),
                    Ok(Form(form.clone())),
                )
                .await
            };
            unavailable(response).await?;
            unavailable(grant(&denied, DEVICE, &[("device_code", &created.device_code)]).await?)
                .await?;
            assert!(state
                .device
                .code_store
                .try_lookup_by_user_code_async(created.user_code.clone())
                .await?
                .is_some());
        }
        let response = if approve {
            web::device_flow::device_approve(
                State(state.clone()),
                remote(),
                OriginalUri("/device/approve".parse()?),
                headers,
                Ok(Form(form)),
            )
            .await
        } else {
            web::device_flow::device_deny(
                State(state.clone()),
                remote(),
                OriginalUri("/device/deny".parse()?),
                headers,
                Ok(Form(form)),
            )
            .await
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !state
                .device
                .csrf_store
                .clone()
                .try_validate_async(csrf.clone())
                .await?
        );
        finish_poll(&state, &created.device_code, approve).await?;
    }
    Ok(())
}

async fn finish_poll(state: &web::AppState, device_code: &str, approve: bool) -> TestResult {
    if approve {
        // A pending-state gate must not poll, consume, or throttle the approved grant either.
        for denied in unavailable_states(state) {
            unavailable(grant(&denied, DEVICE, &[("device_code", device_code)]).await?).await?;
        }
        let response = grant(state, DEVICE, &[("device_code", device_code)]).await?;
        let status = response.status();
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = body["access_token"]
            .as_str()
            .ok_or("device token missing")?;
        assert!(state
            .tokens
            .store
            .try_verify_access_token_async(token.into())
            .await?
            .is_some());
    } else {
        assert!(matches!(
            state
                .device
                .code_store
                .try_poll_async(device_code.into(), "namespace-client".into(), None, None)
                .await?,
            DevicePollResult::AccessDenied
        ));
    }
    Ok(())
}
