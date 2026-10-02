use super::*;
use snapshot_test_hook::Phase;
use tokio::sync::Barrier;

fn code_fields(state: &AppState) -> TestResult<Vec<(String, String)>> {
    let req = serde_json::from_value(
        json!({"dpop_jkt":null,"response_type":"code","client_id":BASIC,
        "redirect_uri":REDIRECT,"scope":"api.read","code_challenge":CHALLENGE,"code_challenge_method":"S256"}),
    )?;
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code(req, "snapshot-user".into())?;
    Ok(vec![
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), code),
        ("redirect_uri".into(), REDIRECT.into()),
        ("code_verifier".into(), VERIFIER.into()),
    ])
}

pub(super) async fn request_fields(
    state: &AppState,
    grant: &str,
) -> TestResult<Vec<(String, String)>> {
    match grant {
        "authorization_code" => code_fields(state),
        "refresh_token" => Ok(vec![
            ("grant_type".into(), grant.into()),
            ("refresh_token".into(), refresh_seed::seed_grant(state)?),
            ("scope".into(), "api.read".into()),
        ]),
        crate::policy::DEVICE_CODE_GRANT_TYPE => {
            let (status, device) = send(
                state,
                "/device_authorization",
                &[("scope", "api.read")],
                Some(&basic()),
            )
            .await?;
            assert_eq!(status, StatusCode::OK, "{device}");
            assert!(state.device.code_store.try_approve(
                device["user_code"].as_str().ok_or("user code")?,
                "snapshot-user"
            )?);
            Ok(vec![
                ("grant_type".into(), grant.into()),
                (
                    "device_code".into(),
                    device["device_code"].as_str().ok_or("device code")?.into(),
                ),
            ])
        }
        crate::policy::JWT_BEARER_GRANT_TYPE => {
            let mut value = claims(state, "/token")?;
            value["iss"] = json!(BASIC);
            value["sub"] = json!("snapshot-user");
            Ok(vec![
                ("grant_type".into(), grant.into()),
                ("assertion".into(), sign(&value)?),
                ("scope".into(), "api.read".into()),
            ])
        }
        "client_credentials" => Ok(vec![
            ("grant_type".into(), grant.into()),
            ("audience".into(), BASIC.into()),
        ]),
        _ => Err("unexpected fixture grant".into()),
    }
}

async fn held_request(state: &AppState, grant: &str, phase: Phase) -> TestResult {
    let fields = request_fields(state, grant).await?;
    let app = crate::web::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    let request = Request::post("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, basic())
        .body(Body::from(serde_urlencoded::to_string(&fields)?))?;
    let observed = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let response = snapshot_test_hook::OBSERVATION.scope(
        (phase, observed.clone(), resume.clone()),
        app.oneshot(request),
    );
    let replace = async {
        observed.wait().await;
        let result = replace_client(state).await;
        resume.wait().await;
        result
    };
    let (response, replaced) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        tokio::join!(response, replace)
    })
    .await?;
    replaced?;
    let response = response?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let status = response.status();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(status, StatusCode::OK, "{grant}: {body}");
    let token = body["access_token"].as_str().ok_or("access token")?;
    let stored = state
        .tokens
        .store
        .try_verify_access_token_async(token.into())
        .await?
        .ok_or("published access token")?;
    assert_eq!(stored.client_id, BASIC);
    assert_eq!(stored.scope.as_deref(), Some("api.read"));
    if grant == "refresh_token" {
        let previous = &fields[1].1;
        let replacement = body["refresh_token"]
            .as_str()
            .ok_or("replacement refresh")?;
        assert_ne!(replacement, previous);
        assert!(
            state
                .tokens
                .store
                .try_get_refresh_token(previous)?
                .ok_or("previous refresh")?
                .rotated
        );
    }
    next_request_refusals(state, grant, fields).await
}

async fn next_request_refusals(
    state: &AppState,
    grant: &str,
    fields: Vec<(String, String)>,
) -> TestResult {
    let count = state.tokens.store.try_snapshot()?.access_tokens.len();
    let borrowed: Vec<_> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let (status, body) = send(state, "/token", &borrowed, Some(&basic())).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "next request: {body}");
    assert_eq!(body["error"], "invalid_client");
    let next_fields = if grant == "authorization_code" {
        code_fields(state)?
    } else {
        fields
    };
    let mut next: Vec<_> = next_fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    next.extend([("client_id", BASIC), ("client_secret", NEXT_SECRET)]);
    let (status, body) = send(state, "/token", &next, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "removed grant: {body}");
    assert_eq!(body["error"], "unauthorized_client");
    assert_eq!(
        state.tokens.store.try_snapshot()?.access_tokens.len(),
        count
    );
    Ok(())
}

async fn scenario(grant: &str, phase: Phase) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL required; no silent skip")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = all_grants_fixture(&pool, &env).await?;
        held_request(&state, grant, phase).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn token_snapshot_code_uses_authenticated_grants_after_reload() -> TestResult {
    scenario("authorization_code", Phase::AfterAuthentication).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn token_snapshot_refresh_authenticates_captured_credentials_after_reload() -> TestResult {
    scenario("refresh_token", Phase::BeforeAuthentication).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn token_snapshot_device_uses_authenticated_grants_after_reload() -> TestResult {
    scenario(
        crate::policy::DEVICE_CODE_GRANT_TYPE,
        Phase::AfterAuthentication,
    )
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn token_snapshot_jwt_uses_authenticated_scope_and_keys_after_reload() -> TestResult {
    scenario(
        crate::policy::JWT_BEARER_GRANT_TYPE,
        Phase::AfterAuthentication,
    )
    .await
}
