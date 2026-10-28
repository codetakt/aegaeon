use super::{
    browser_consumption::session,
    direct::grant,
    support::{fixture, remote, unavailable, unavailable_states, TestResult},
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
    for approve in [true, false] {
        let (mut state, _) = fixture().await?;
        Arc::make_mut(&mut state.cfg).enable_device_authz = true;
        state.validate_subject_namespace().await?;
        let mut client = test_support::sample_registered_client("namespace-client");
        client.allowed_grant_types.push(DEVICE.into());
        state.clients.register(client);
        let created = state
            .device
            .code_store
            .try_create(
                "namespace-client",
                Some("read"),
                None,
                "https://issuer.example/device",
            )
            .ok_or("device request missing")?;
        let sid = session(&state, "namespace-user")?;
        let csrf = state.device.csrf_store.try_generate()?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={sid}; aegaeon_device_csrf={csrf}",
                web::AUTH_SESSION_COOKIE_NAME
            )
            .parse()?,
        );
        let form = vec![
            ("csrf_token".into(), csrf.clone()),
            ("user_code".into(), created.user_code.clone()),
        ];
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
                .try_lookup_by_user_code(&created.user_code)?
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
        assert!(!state.device.csrf_store.try_validate(&csrf)?);
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
        assert!(state.tokens.store.try_verify_access_token(token)?.is_some());
    } else {
        assert!(matches!(
            state
                .device
                .code_store
                .try_poll(device_code, "namespace-client", None, None)?,
            DevicePollResult::AccessDenied
        ));
    }
    Ok(())
}
