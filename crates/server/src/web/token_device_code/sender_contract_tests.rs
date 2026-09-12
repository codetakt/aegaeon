use super::*;
use crate::authcode::types::SenderBinding;
use crate::web::test_support::{
    cleanup_test_environment, finish_test, setup_test_environment, test_app_state, test_pg_pool,
    TestResult,
};
use crate::web::token_form::token_form_from_params;
use crate::web::token_sender_binding::token_cnf_from_sender_binding;
use axum::body::to_bytes;
use serde_json::Value;

fn context(binding: Option<SenderBinding>) -> TestResult<TokenEndpointContext> {
    let params = vec![("grant_type".into(), DEVICE_CODE_GRANT_TYPE.into())];
    let form = token_form_from_params(&params, "https://issuer.example")
        .map_err(|_| "device form rejected")?;
    Ok(TokenEndpointContext {
        request_id: "device-sender-contract".into(),
        params,
        form,
        grant_type: DEVICE_CODE_GRANT_TYPE.into(),
        client_id: "device-client".into(),
        resource: None,
        sender_constraint: crate::policy::SenderConstraint::None,
        enforce_refresh_sender_binding: true,
        authorization_code_grant_allowed: false,
        refresh_grant_allowed: false,
        cnf_for_at: token_cnf_from_sender_binding(binding.as_ref()),
        sender_binding: binding,
        issuer_req: serde_json::from_value(json!({
            "grant_type": DEVICE_CODE_GRANT_TYPE, "client_id": "device-client"
        }))?,
    })
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn device_response_and_saved_token_describe_committed_sender_binding() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = test_app_state(pool.clone(), &env).await?;
        for (binding, expected_type) in [
            (None, "Bearer"),
            (
                Some(SenderBinding::DPoP {
                    jkt: "test-key".into(),
                }),
                "DPoP",
            ),
            (
                Some(SenderBinding::Mtls {
                    fingerprint: format!("SHA256:{}", "AB".repeat(32)),
                }),
                "Bearer",
            ),
        ] {
            let ctx = context(binding.clone())?;
            let response = approved_device_grant_response(
                &state,
                &ctx,
                ApprovedDeviceGrant {
                    client_id: "device-client".into(),
                    user_id: "user".into(),
                    scope: Some("read".into()),
                    resource: None,
                },
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
            assert_eq!(body["token_type"], expected_type);
            let token = body["access_token"]
                .as_str()
                .ok_or("access token missing")?;
            let saved = state
                .tokens
                .store
                .try_verify_access_token(token)?
                .ok_or("saved token missing")?;
            assert_eq!(saved.token_type, expected_type);
            assert_eq!(saved.cnf, ctx.cnf_for_at);
            let (_, meta) = state
                .tokens
                .validator
                .validate_bearer_token_with_meta_async(format!("Bearer {token}"))
                .await?;
            assert_eq!(meta.ok_or("metadata missing")?.sender_binding, binding);
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
