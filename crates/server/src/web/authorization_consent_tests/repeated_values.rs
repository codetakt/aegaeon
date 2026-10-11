//! Actual router/Redis code issuance and token exchange with RP-controlled values.
use super::*;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::json;

const OTHER: &str = "repeat-client";
const RP_STATE: &str = "same state +&= 値";
const RP_NONCE: &str = "same nonce +&= 値";
const REDIRECT: &str = "https://client.example.com/callback";

async fn shared_fixture(pool: &PgPool, env: &TestEnvironment) -> TestResult<(AppState, String)> {
    let (mut state, sid) = fixture(pool, env).await?;
    let mut client = state.clients.try_get(CLIENT)?.ok_or("client missing")?;
    client.client_id = OTHER.to_string();
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".to_string()],
        "repeat-registration",
        "repeat-test",
    )
    .await?;
    // Optional state is explicitly allowed only in this fixture. Production
    // presence requirements are unchanged and checked separately below.
    sqlx::query(
        "UPDATE aegaeon.oauth_profiles SET require_state_parameter=false WHERE environment_id=$1",
    )
    .bind(env.environment_id)
    .execute(pool)
    .await?;
    update_test_policy(&mut state, |p| p.require_state_parameter = false).await?;
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(pool, &state.clients)
        .await?;
    request_objects::shared_protocol_stores(&mut state)?;
    state
        .protocol
        .par_endpoint
        .register_client(crate::par::Client {
            client_id: OTHER.to_string(),
            client_secret: None,
            token_endpoint_auth_method: "none".to_string(),
            redirect_uris: client.redirect_uris,
            allowed_scopes: client.allowed_scopes,
        });
    Ok((state, sid))
}

fn fields<'a>(
    client: &'a str,
    state_value: Option<&'a str>,
    nonce: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut fields = vec![
        ("client_id", client),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        (
            "scope",
            if nonce.is_some() {
                "openid email"
            } else {
                "email"
            },
        ),
        (
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ),
        ("code_challenge_method", "S256"),
    ];
    if let Some(value) = state_value {
        fields.push(("state", value));
    }
    if let Some(value) = nonce {
        fields.push(("nonce", value));
    }
    fields
}

fn signed(state: &AppState, values: &[(&str, &str)]) -> TestResult<String> {
    let mut claims = serde_json::Map::new();
    for (name, value) in values {
        claims.insert((*name).to_string(), json!(value));
    }
    let now = crate::util::now_unix_epoch_secs()?;
    claims.insert("iss".into(), claims["client_id"].clone());
    claims.insert("aud".into(), json!(state.issuer.as_str()));
    claims.insert("iat".into(), json!(now));
    claims.insert("exp".into(), json!(now + 60));
    claims.insert("jti".into(), json!(Uuid::new_v4().to_string()));
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("oauth-authz-req+jwt".to_string());
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(include_bytes!(
            "../../../tests/fixtures/rsa2048-private.pk8.pem"
        ))?,
    )?)
}

async fn uri(
    state: &AppState,
    sid: &str,
    client: &str,
    state_value: Option<&str>,
    nonce: Option<&str>,
    mode: &str,
) -> TestResult<String> {
    let mut values = fields(client, state_value, nonce);
    let jwt;
    if mode.contains("jar") {
        jwt = signed(state, &values)?;
        values = vec![("client_id", client), ("request", &jwt)];
    } else {
        values.push(("iss", state.issuer.as_str()));
    }
    if mode.starts_with("par") {
        let (status, body) = send(state, sid, "/par", Some(values), None).await?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let result: Value = serde_json::from_str(&body)?;
        return Ok(format!(
            "/authorize?{}",
            serde_urlencoded::to_string([
                ("client_id", client),
                (
                    "request_uri",
                    result["request_uri"].as_str().ok_or("PAR URI")?
                )
            ])?
        ));
    }
    Ok(format!(
        "/authorize?{}",
        serde_urlencoded::to_string(values)?
    ))
}

async fn exchange(
    state: &AppState,
    sid: &str,
    code: &str,
    client: &str,
    redirect: &str,
    verifier: &str,
) -> TestResult<(StatusCode, Value)> {
    let (status, body) = send(
        state,
        sid,
        "/token",
        Some(vec![
            ("grant_type", "authorization_code"),
            ("client_id", client),
            ("code", code),
            ("redirect_uri", redirect),
            ("code_verifier", verifier),
        ]),
        None,
    )
    .await?;
    Ok((status, serde_json::from_str(&body)?))
}
fn check_id_token(
    state: &AppState,
    client: &str,
    response: &Value,
    nonce: Option<&str>,
) -> TestResult {
    if let Some(nonce) = nonce {
        let cfg = state.oidc.config.as_ref().ok_or("OIDC config")?;
        let jwk = &cfg.jwks().keys[0];
        let key = DecodingKey::from_rsa_components(
            jwk.n.as_deref().ok_or("RSA n")?,
            jwk.e.as_deref().ok_or("RSA e")?,
        )?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[client]);
        validation.set_issuer(&[state.issuer.as_str()]);
        let claims = jsonwebtoken::decode::<Value>(
            response["id_token"].as_str().ok_or("ID Token")?,
            &key,
            &validation,
        )?
        .claims;
        assert_eq!(claims["nonce"], nonce);
    } else {
        assert!(response.get("id_token").is_none());
    }
    Ok(())
}

async fn repeats(state: &AppState, sid: &str, mode: &str) -> TestResult {
    for (state_value, nonce) in [
        (Some(RP_STATE), None),
        (None, Some(RP_NONCE)),
        (Some(RP_STATE), Some(RP_NONCE)),
    ] {
        let mut issued = Vec::new();
        for client in [CLIENT, CLIENT, OTHER, OTHER] {
            let request = uri(state, sid, client, state_value, nonce, mode).await?;
            let (status, body) = send(state, sid, &request, None, None).await?;
            assert_eq!(status, StatusCode::OK, "{mode}/{client}: {body}");
            let response: Value = serde_json::from_str(&body)?;
            assert_eq!(response.get("state").and_then(Value::as_str), state_value);
            let code = response["code"].as_str().ok_or("code missing")?.to_string();
            let stored = state
                .tokens
                .issuer
                .code_store
                .try_get_code(&code)?
                .ok_or("stored code")?;
            assert_eq!(stored.state.as_deref(), state_value);
            assert_eq!(stored.nonce.as_deref(), nonce);
            assert_eq!(stored.client_id, client);
            assert!(!issued.iter().any(|(old, _, _)| old == &code));
            issued.push((code, client, request));
        }
        // Identical values cannot make invalid credentials select another code.
        for (code, client, request) in issued {
            for (wrong_client, redirect, verifier) in [
                (
                    if client == CLIENT { OTHER } else { CLIENT },
                    REDIRECT,
                    VERIFIER,
                ),
                (client, "https://other.example/callback", VERIFIER),
                (
                    client,
                    REDIRECT,
                    "wrong-verifier-which-is-long-enough-to-pass-syntax",
                ),
            ] {
                let (status, response) =
                    exchange(state, sid, &code, wrong_client, redirect, verifier).await?;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
                assert!(response.get("access_token").is_none());
            }
            let (a, b) = tokio::join!(
                exchange(state, sid, &code, client, REDIRECT, VERIFIER),
                exchange(state, sid, &code, client, REDIRECT, VERIFIER)
            );
            let results = [a?, b?];
            assert_eq!(
                results.iter().filter(|(s, _)| *s == StatusCode::OK).count(),
                1,
                "{results:?}"
            );
            for (status, response) in results {
                if status == StatusCode::OK {
                    check_id_token(state, client, &response, nonce)?;
                } else {
                    assert_eq!(status, StatusCode::BAD_REQUEST);
                    assert!(response.get("access_token").is_none());
                }
            }
            assert_eq!(
                exchange(state, sid, &code, client, REDIRECT, VERIFIER)
                    .await?
                    .0,
                StatusCode::BAD_REQUEST
            );
            if mode != "plain" {
                let (status, body) = send(state, sid, &request, None, None).await?;
                assert_eq!(
                    status,
                    StatusCode::BAD_REQUEST,
                    "one-time input replay: {body}"
                );
            }
        }
    }
    assert_eq!(state.tokens.issuer.try_state_count()?, 1);
    assert_eq!(state.tokens.issuer.try_nonce_count()?, 1);
    Ok(())
}
async fn scenario(mode: &str) -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (state, sid) = shared_fixture(&pool, &env).await?;
        repeats(&state, &sid, mode).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
macro_rules! real_repeat_test {
    ($name:ident,$mode:literal) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL and shared Redis code/token/PAR/JTI stores"]
        async fn $name() -> TestResult {
            scenario($mode).await
        }
    };
}
real_repeat_test!(
    shared_redis_repeated_rp_values_plain_authorize_token,
    "plain"
);
real_repeat_test!(shared_redis_repeated_rp_values_par_authorize_token, "par");
real_repeat_test!(shared_redis_repeated_rp_values_jar_authorize_token, "jar");
real_repeat_test!(
    shared_redis_repeated_rp_values_par_jar_authorize_token,
    "par-jar"
);

#[tokio::test]
#[ignore = "requires PostgreSQL and shared Redis code/token/PAR/JTI stores"]
async fn shared_redis_repeated_rp_values_preserve_required_presence_policy() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result=async {
        let (mut state,sid)=shared_fixture(&pool,&env).await?;
        let mut values=fields(CLIENT,Some(RP_STATE),None);
        for (name,value) in &mut values { if *name=="scope" {*value="openid";} }
        let request=format!("/authorize?{}",serde_urlencoded::to_string(values)?);
        let (status,body)=send(&state,&sid,&request,None,None).await?;
        assert_eq!(status,StatusCode::BAD_REQUEST,"missing required nonce: {body}");
        sqlx::query("UPDATE aegaeon.oauth_profiles SET require_state_parameter=true WHERE environment_id=$1")
            .bind(env.environment_id).execute(&pool).await?;
        state.readiness=crate::web::ReadinessState::new();
        reload_authorization_runtime(&mut state).await?;
        let request=uri(&state,&sid,CLIENT,None,Some(RP_NONCE),"plain").await?;
        let (status,body)=send(&state,&sid,&request,None,None).await?;
        assert_eq!(status,StatusCode::BAD_REQUEST,"missing required state: {body}");
        assert!(state.tokens.issuer.code_store.try_snapshot()?.codes.is_empty());
        Ok(())
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
