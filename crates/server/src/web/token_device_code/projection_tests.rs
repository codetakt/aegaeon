//! Approved-device issuance and online metadata checks, with PostgreSQL projections.
//! Device polling/approval and deployed TLS are outside this handler fixture.
use super::*;
use crate::application_authorization::{inorii::CLAIM_NAME, Authority};
use crate::web::test_support::*;
use axum::body::to_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use std::sync::Arc;

const CLIENT: &str = "device-client";
const SUBJECT: &str = "device-user";

fn context() -> TestResult<TokenEndpointContext> {
    let params = vec![("grant_type".into(), DEVICE_CODE_GRANT_TYPE.into())];
    let form = crate::web::token_form::token_form_from_params(&params, "https://issuer.example")
        .map_err(|_| "device form rejected")?;
    Ok(TokenEndpointContext {
        request_id: "device-projection".into(),
        params,
        form,
        grant_type: DEVICE_CODE_GRANT_TYPE.into(),
        client_id: CLIENT.into(),
        resource: None,
        sender_constraint: crate::policy::SenderConstraint::None,
        enforce_refresh_sender_binding: true,
        authorization_code_grant_allowed: false,
        refresh_grant_allowed: false,
        cnf_for_at: None,
        sender_binding: None,
        issuer_req: serde_json::from_value(json!({
            "grant_type": DEVICE_CODE_GRANT_TYPE, "client_id": CLIENT
        }))?,
    })
}

async fn issue(state: &AppState, audience: &str) -> TestResult<Value> {
    let response = approved_device_grant_response(
        state,
        &context()?,
        ApprovedDeviceGrant {
            client_id: CLIENT.into(),
            user_id: SUBJECT.into(),
            scope: Some("read".into()),
            resource: Some(audience.into()),
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 65536).await?,
    )?)
}

async fn fixture(pool: &sqlx::PgPool, env: &TestEnvironment) -> TestResult<AppState> {
    let mut state = test_app_state(pool.clone(), env).await?;
    state.application_authority = Some(Authority {
        projections: pool.clone(),
        memberships: None,
    });
    state.keys.access_token = Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?);
    state.tokens.issuer = Arc::new(
        crate::authcode::TokenIssuer::with_stores(
            Arc::clone(&state.keys.access_token),
            crate::authcode::AuthCodeStore::new_process_local_for_tests(),
            state.tokens.store.as_ref().clone(),
        )
        .with_issuer(env.issuer_url.clone())
        .with_jwt_access_tokens_enabled(true),
    );
    Ok(state)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn device_projection_is_retained_for_claim_release_and_online_revocation() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        let audience = "https://resource.example/allowed";
        let other = "https://resource.example/ordinary-oauth";
        let claims = json!({"roles":["USER"], "organization_roles":[]});
        for (client, subject, roles) in [
            (CLIENT, SUBJECT, claims.clone()),
            (CLIENT, "another-user", json!({"roles":["SUPER_ADMIN"], "organization_roles":[]})),
            ("another-client", SUBJECT, json!({"roles":["SUPER_ADMIN"], "organization_roles":[]})),
        ] {
            seed_test_projection(&pool, &env, client, subject, json!([audience]), roles).await?;
        }
        let mut issued = Vec::new();
        for target in [audience, other] {
            let body = issue(&state, target).await?;
            let token = body["access_token"].as_str().ok_or("missing access token")?.to_owned();
            let payload: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).ok_or("JWT payload")?)?)?;
            assert_eq!(payload["aud"], target);
            assert_eq!(payload["sub"], SUBJECT);
            if target == audience { assert_eq!(payload[CLAIM_NAME], claims); }
            else { assert!(payload.get(CLAIM_NAME).is_none()); }
            let meta = state.tokens.store.try_get_bearer_meta(&token)?.ok_or("metadata")?;
            let projection = meta.application_grant.as_ref().ok_or("projection must be retained")?;
            assert_eq!(projection.client_id, CLIENT);
            assert_eq!(projection.subject, SUBJECT);
            assert_eq!(projection.environment_id, env.environment_id);
            assert_eq!(projection.issuer, env.issuer_url);
            assert_eq!(projection.revision, 1);
            assert_eq!(projection.audiences, vec![audience]);
            assert_eq!(serde_json::to_value(&projection.claims)?, claims);
            assert!(state.tokens.store.try_verify_access_token(&token)?.is_some());
            assert!(super::super::application_authorization::check_resource(&state, &meta, &format!("Bearer {token}")).await.is_ok());
            issued.push(token);
        }
        sqlx::query("UPDATE aegaeon.application_authorizations SET revision=2,source_revision=2,enabled=false WHERE environment_id=$1 AND client_id=$2 AND subject=$3")
            .bind(env.environment_id).bind(CLIENT).bind(SUBJECT).execute(&pool).await?;
        for token in issued {
            let meta = state.tokens.store.try_get_bearer_meta(&token)?.ok_or("metadata")?;
            let response = super::super::application_authorization::check_resource(&state, &meta, &format!("Bearer {token}"))
                .await.err().ok_or("stale device projection accepted")?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(response.headers()["www-authenticate"].to_str()?.contains("Bearer"));
            let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
            assert_eq!(body["error"], "invalid_token");
        }
        Ok(())
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn device_projection_absence_and_authority_failure_are_distinct() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        let body = issue(&state, "https://resource.example/ordinary-oauth").await?;
        let token = body["access_token"].as_str().ok_or("access token")?;
        assert!(state
            .tokens
            .store
            .try_get_bearer_meta(token)?
            .ok_or("metadata")?
            .application_grant
            .is_none());
        let closed = sqlx::postgres::PgPoolOptions::new()
            .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
            .await?;
        closed.close().await;
        state.application_authority = Some(Authority {
            projections: closed,
            memberships: None,
        });
        let response = approved_device_grant_response(
            &state,
            &context()?,
            ApprovedDeviceGrant {
                client_id: CLIENT.into(),
                user_id: SUBJECT.into(),
                scope: Some("read".into()),
                resource: None,
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "temporarily_unavailable");
        assert!(body.get("access_token").is_none());
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
