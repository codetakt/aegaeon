use super::{
    authorization_fixture as f,
    support::{remote, unavailable, unavailable_states, TestResult},
};
use crate::web::{self, AppState};
use axum::{
    body::to_bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    Form,
};
use base64::Engine;
use serde_json::Value;

async fn request(state: &AppState, kind: &str, extra: &[(&str, &str)]) -> TestResult<Response> {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/x-www-form-urlencoded".parse()?);
    let mut form = vec![
        ("grant_type".to_owned(), kind.to_owned()),
        ("client_id".into(), f::CLIENT.into()),
    ];
    form.extend(
        extra
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into())),
    );
    Ok(Box::pin(web::token_endpoint::token(
        State(state.clone()),
        remote(),
        OriginalUri("/token".parse()?),
        headers,
        Ok(Form(form)),
    ))
    .await)
}
async fn result(response: Response, status: StatusCode) -> TestResult<Value> {
    let actual = response.status();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(actual, status, "{body}");
    Ok(body)
}

pub(super) async fn redeem(state: &AppState, code: &str) -> TestResult {
    let extra = [
        ("code", code),
        ("redirect_uri", "https://client.example.com/callback"),
        (
            "code_verifier",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        ),
    ];
    let original = serde_json::to_value(
        state
            .tokens
            .issuer
            .code_store
            .try_get_code_async(code.into())
            .await?,
    )?;
    for denied in unavailable_states(state) {
        unavailable(request(&denied, "authorization_code", &extra).await?).await?;
        assert_eq!(
            serde_json::to_value(
                state
                    .tokens
                    .issuer
                    .code_store
                    .try_get_code_async(code.into())
                    .await?
            )?,
            original
        );
    }
    let issued = result(
        request(state, "authorization_code", &extra).await?,
        StatusCode::OK,
    )
    .await?;
    assert!(state
        .tokens
        .issuer
        .code_store
        .try_get_code_async(code.into())
        .await?
        .is_none());
    let access = issued["access_token"].as_str().ok_or("access missing")?;
    assert!(state
        .tokens
        .store
        .try_verify_access_token_async(access.into())
        .await?
        .is_some());
    // This inspects an ID Token emitted by the real issuer; verification is covered by issuer tests.
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(
            issued["id_token"]
                .as_str()
                .ok_or("ID Token missing")?
                .split('.')
                .nth(1)
                .ok_or("claims missing")?,
        )?,
    )?;
    let sid = uuid::Uuid::parse_str(claims["sid"].as_str().ok_or("sid missing")?)?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let persisted: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM aegaeon.runtime_oidc_sessions s JOIN aegaeon.runtime_oidc_clients c USING(namespace,sid) WHERE s.namespace=$1 AND s.sid=$2 AND s.user_id=$3 AND c.client_id=$4 AND s.logout_jti IS NULL)")
        .bind(namespace.flow_namespace("oauth", "grant")).bind(sid).bind("namespace-user").bind(f::CLIENT).fetch_one(&state.db_pool).await?;
    assert!(
        persisted,
        "ID Token sid and client binding must commit with the tokens"
    );
    let reused = result(
        request(state, "authorization_code", &extra).await?,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    assert_eq!(reused["error"], "invalid_grant");
    let refresh = issued["refresh_token"].as_str().ok_or("refresh missing")?;
    for denied in unavailable_states(state) {
        unavailable(request(&denied, "refresh_token", &[("refresh_token", refresh)]).await?)
            .await?;
        assert!(
            !state
                .tokens
                .store
                .try_is_refresh_revoked_async(refresh.into())
                .await?
        );
    }
    let rotated = result(
        request(state, "refresh_token", &[("refresh_token", refresh)]).await?,
        StatusCode::OK,
    )
    .await?;
    let successor = rotated["refresh_token"]
        .as_str()
        .ok_or("successor missing")?;
    assert_ne!(refresh, successor);
    let next_access = rotated["access_token"]
        .as_str()
        .ok_or("successor access missing")?;
    assert!(state
        .tokens
        .store
        .try_verify_access_token_async(next_access.into())
        .await?
        .is_some());
    let reuse = result(
        request(state, "refresh_token", &[("refresh_token", refresh)]).await?,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    assert_eq!(reuse["error"], "invalid_grant");
    assert!(state
        .tokens
        .store
        .try_verify_access_token_async(next_access.into())
        .await?
        .is_none());
    assert!(
        state
            .tokens
            .store
            .try_is_refresh_revoked_async(successor.into())
            .await?
    );
    Ok(())
}
