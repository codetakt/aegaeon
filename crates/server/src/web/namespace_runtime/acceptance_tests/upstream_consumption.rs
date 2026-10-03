use super::support::{fixture, remote, unavailable, unavailable_states, TestResult};
use crate::{
    upstream::{UpstreamAuthRequest, UpstreamConnectionContext},
    web,
};
use axum::{
    body::to_bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime};

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_upstream_callback_preserves_state_before_normal_error_completion(
) -> TestResult {
    let (state, env) = fixture().await?;
    let id = uuid::Uuid::new_v4().to_string();
    let now = SystemTime::now();
    let request = UpstreamAuthRequest {
        state: id.clone(),
        nonce: "namespace-nonce".into(),
        code_verifier: Some("verifier".into()),
        acr: None,
        issuer: "https://upstream.example".into(),
        client_id: "upstream-client".into(),
        client_secret: None,
        client_auth_method: "none".into(),
        context: UpstreamConnectionContext::new(
            uuid::Uuid::new_v4(),
            env.team_id,
            env.tenant_id,
            env.environment_id,
            uuid::Uuid::new_v4(),
        ),
        token_endpoint: "https://upstream.example/token".into(),
        jwks_uri: "https://upstream.example/jwks".into(),
        redirect_uri: format!("{}/oauth/upstream/example/callback", state.issuer),
        return_to: None,
        max_age: None,
        require_iss_parameter: true,
        jit_provisioning_policy: None,
        attribute_mappings: vec![],
        claim_release_policy: None,
        logout_policy: None,
        issued_at: now,
        expires_at: now + Duration::from_secs(300),
    };
    state.upstream.auth_store.try_insert(request)?;
    for denied in unavailable_states(&state) {
        // Check both success-shaped and upstream-error callback branches before either consumes.
        for query in [
            json!({"state":id,"code":"retained-code","iss":"https://upstream.example"}),
            json!({"state":id,"error":"access_denied"}),
        ] {
            unavailable(
                web::upstream_callback::upstream_callback(
                    State(denied.clone()),
                    remote(),
                    HeaderMap::new(),
                    OriginalUri("/oauth/upstream/example/callback".parse()?),
                    Path("example".into()),
                    Query(serde_json::from_value(query)?),
                )
                .await,
            )
            .await?;
        }
    }
    let preserved = state
        .upstream
        .auth_store
        .try_consume(&id)?
        .ok_or("denied callbacks consumed upstream state")?;
    assert_eq!(preserved.state, id);
    assert_eq!(preserved.nonce, "namespace-nonce");
    state.upstream.auth_store.try_insert(preserved)?;
    let response = web::upstream_callback::upstream_callback(
        State(state.clone()),
        remote(),
        HeaderMap::new(),
        OriginalUri("/oauth/upstream/example/callback".parse()?),
        Path("example".into()),
        Query(serde_json::from_value(
            json!({"state":id,"error":"access_denied"}),
        )?),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(body["error"], "access_denied");
    assert!(state.upstream.auth_store.try_consume(&id)?.is_none());
    Ok(())
}
