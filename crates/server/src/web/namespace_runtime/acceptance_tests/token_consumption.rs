use super::{
    direct::grant,
    support::{fixture, unavailable, unavailable_states, TestResult},
};
use crate::authcode::types::{AuthorizationCode, AuthorizationCodeInput};
use axum::{body::to_bytes, http::StatusCode, response::Response};
use serde_json::Value;

async fn success(response: Response) -> TestResult<Value> {
    let status = response.status();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].as_str().is_some());
    Ok(body)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_preserves_code_and_refresh_then_matching_permit_exchanges_and_rotates(
) -> TestResult {
    let (state, _) = fixture().await?;
    let verifier = "namespace-verifier-with-at-least-forty-three-characters";
    let mut input = AuthorizationCodeInput::new(
        "namespace-client".into(),
        "namespace-user".into(),
        Some("https://client.example/callback".into()),
    );
    input.scope = Some("read offline_access".into());
    input.code_challenge = Some(crate::upstream::pkce_challenge(verifier));
    input.code_challenge_method = Some("S256".into());
    let code = state
        .tokens
        .issuer
        .code_store
        .store_code(AuthorizationCode::new(input))?;
    let extra = [
        ("code", code.as_str()),
        ("code_verifier", verifier),
        ("redirect_uri", "https://client.example/callback"),
    ];
    let before = serde_json::to_value(state.tokens.issuer.code_store.try_get_code(&code)?)?;
    let version = state.tokens.store.try_snapshot()?.version;
    for denied in unavailable_states(&state) {
        unavailable(grant(&denied, "authorization_code", &extra).await?).await?;
        assert_eq!(
            serde_json::to_value(state.tokens.issuer.code_store.try_get_code(&code)?)?,
            before
        );
        assert_eq!(state.tokens.store.try_snapshot()?.version, version);
    }
    let issued = success(grant(&state, "authorization_code", &extra).await?).await?;
    assert!(state
        .tokens
        .issuer
        .code_store
        .try_get_code(&code)?
        .is_none());
    let access = issued["access_token"].as_str().ok_or("access missing")?;
    assert!(state
        .tokens
        .store
        .try_verify_access_token(access)?
        .is_some());
    let refresh = issued["refresh_token"].as_str().ok_or("refresh missing")?;
    let before = serde_json::to_value(state.tokens.store.try_get_refresh_token(refresh)?)?;
    let version = state.tokens.store.try_snapshot()?.version;
    for denied in unavailable_states(&state) {
        unavailable(grant(&denied, "refresh_token", &[("refresh_token", refresh)]).await?).await?;
        assert_eq!(
            serde_json::to_value(state.tokens.store.try_get_refresh_token(refresh)?)?,
            before
        );
        assert!(!state.tokens.store.try_is_refresh_revoked(refresh)?);
        assert_eq!(state.tokens.store.try_snapshot()?.version, version);
    }
    let rotated =
        success(grant(&state, "refresh_token", &[("refresh_token", refresh)]).await?).await?;
    let successor = rotated["refresh_token"]
        .as_str()
        .ok_or("successor missing")?;
    assert_ne!(successor, refresh);
    assert!(state
        .tokens
        .store
        .try_get_refresh_token(successor)?
        .is_some());
    assert!(
        state.tokens.store.try_get_refresh_token(refresh)?.is_none()
            || state.tokens.store.try_is_refresh_revoked(refresh)?
    );
    Ok(())
}
