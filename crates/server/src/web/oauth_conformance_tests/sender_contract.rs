//! Request/metadata contracts; the unit-test DPoP verifier checks claims, not signatures.
use super::*;
use crate::authcode::types::{AccessToken, BearerTokenMeta, BearerTokenMetaInput, SenderBinding};
use crate::web::test_support::{
    cleanup_test_environment, finish_test, setup_test_environment, test_app_state, test_pg_pool,
};
use crate::web::AppState;
use axum::extract::{ConnectInfo, OriginalUri, State};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn proof(method: &str, path: &str, token: &str) -> Result<String, Box<dyn std::error::Error>> {
    let header = json!({"typ":"dpop+jwt", "alg":"ES256", "jwk":{
        "kty":"EC", "crv":"P-256", "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}});
    let payload = json!({"htm":method, "htu":format!("http://localhost{path}"),
        "iat":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "jti":uuid::Uuid::new_v4().to_string(), "ath":URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(token.as_bytes()))});
    Ok(format!(
        "{}.{}.unit-test-signature",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
    ))
}

async fn install_token(state: &AppState, path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut access = AccessToken::new(
        "client".into(),
        "user".into(),
        Some("openid read".into()),
        60,
    );
    let sample = proof("GET", path, &access.token)?;
    let jkt = crate::util::compute_dpop_jkt_from_proof(&sample).ok_or("fixture thumbprint")?;
    access.cnf = Some(crate::authcode::types::CnfClaim::Jkt(jkt.clone()));
    access.token_type = "DPoP".into();
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        granted_scopes: vec!["openid".into(), "read".into()],
        audience: format!("{}{path}", state.issuer),
        sender_binding: Some(SenderBinding::DPoP { jkt }),
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: access.created_at,
        expires_at: access.created_at + Duration::from_secs(60),
        refresh_parent: None,
    });
    let token = access.token.clone();
    state
        .tokens
        .store
        .store_issued_grant_async(access, None, meta)
        .await?;
    Ok(token)
}

fn headers(
    scheme: &str,
    method: &str,
    path: &str,
    token: &str,
) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("{scheme} {token}").parse()?);
    headers.insert("dpop", proof(method, path, token)?.parse()?);
    Ok(headers)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn upstream_refresh_rejects_bearer_downgrade_with_proof_and_preserves_token() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = test_app_state(pool.clone(), &env).await?;
        let path = "/oauth/upstream/refresh";
        let token = install_token(&state, path).await?;
        for scheme in ["DPoP", "Bearer", "DPoP"] {
            let outcome = crate::web::upstream_refresh_links::authenticate_upstream_refresh_caller(
                &state,
                &path.parse()?,
                &headers(scheme, "POST", path, &token)?,
                state.issuer.as_str(),
            )
            .await;
            if scheme == "DPoP" {
                assert!(outcome.is_ok(), "valid sender rejected");
            } else {
                let response = outcome.err().ok_or("Bearer downgrade accepted")?;
                assert_eq!(
                    response.headers()["www-authenticate"],
                    "Bearer realm=\"aegaeon\", error=\"invalid_token\""
                );
                error(response, StatusCode::UNAUTHORIZED, "invalid_token").await?;
            }
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn userinfo_get_and_post_bearer_downgrade_challenge_the_attempted_scheme() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = test_app_state(pool.clone(), &env).await?;
        state.oidc.userinfo_endpoint =
            Some(Arc::new(crate::oidc::userinfo::UserinfoEndpoint::new(
                state.tokens.validator.as_ref().clone(),
                pool.clone(),
                env.issuer_url.clone(),
            )));
        let token = install_token(&state, "/userinfo").await?;
        for method in ["GET", "POST"] {
            for scheme in ["DPoP", "Bearer", "DPoP"] {
                let mut request_headers = headers(scheme, method, "/userinfo", &token)?;
                let remote = ConnectInfo("127.0.0.1:12345".parse()?);
                let uri = OriginalUri("/userinfo".parse()?);
                let response = if method == "GET" {
                    crate::web::userinfo::userinfo_get(
                        State(state.clone()),
                        remote,
                        uri,
                        request_headers,
                    )
                    .await
                } else {
                    request_headers
                        .insert("content-type", "application/x-www-form-urlencoded".parse()?);
                    crate::web::userinfo::userinfo_post(
                        State(state.clone()),
                        remote,
                        uri,
                        request_headers,
                        Ok(axum::extract::Form(Vec::new())),
                    )
                    .await
                };
                if scheme == "DPoP" {
                    assert_eq!(response.status(), StatusCode::OK);
                } else {
                    assert_eq!(
                        response.headers()["www-authenticate"],
                        "Bearer realm=\"aegaeon\", error=\"invalid_token\""
                    );
                    error(response, StatusCode::UNAUTHORIZED, "invalid_token").await?;
                }
            }
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
