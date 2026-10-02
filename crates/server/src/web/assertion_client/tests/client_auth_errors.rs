//! Exact response and effect checks through the router and shared Redis stores.
use super::*;

pub(super) fn password_fields(path: &str, client: &str) -> Vec<(String, String)> {
    let mut fields: Vec<_> = super::fields(path, "")
        .into_iter()
        .filter(|(name, _)| !name.starts_with("client_assertion") && *name != "client_id")
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    fields.push(("client_id".into(), client.into()));
    fields
}

pub(super) fn borrowed(fields: &[(String, String)]) -> Vec<(&str, &str)> {
    fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

fn password_header(client: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client}:{secret}")))
}

fn redis_keys(state: &AppState) -> TestResult<std::collections::BTreeSet<String>> {
    let mut conn =
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?.get_connection()?;
    Ok(redis::cmd("KEYS")
        .arg(format!("aegaeon:{{runtime:{}:*", state.environment_id))
        .query(&mut conn)?)
}

async fn recognized_failures(state: &AppState) -> TestResult {
    for path in PATHS {
        for auth in [
            "Basic not-base64".to_string(),
            password_header(BASIC, "wrong"),
            password_header("unknown", SECRET),
            password_header(POST, SECRET),
        ] {
            reject(
                state,
                path,
                &borrowed(&password_fields(path, BASIC)),
                Some(&auth),
            )
            .await?;
        }
        // Keep method mismatch independent from an outer/credential ID mismatch.
        reject(
            state,
            path,
            &borrowed(&password_fields(path, POST)),
            Some(&password_header(POST, SECRET)),
        )
        .await?;
        let mut basic_as_post = password_fields(path, BASIC);
        basic_as_post.push(("client_secret".into(), SECRET.into()));
        reject(state, path, &borrowed(&basic_as_post), None).await?;
        reject(
            state,
            path,
            &borrowed(&password_fields(path, "unknown")),
            Some(&password_header("unknown", SECRET)),
        )
        .await?;
        let mut post = password_fields(path, POST);
        post.push(("client_secret".into(), "wrong".into()));
        reject(state, path, &borrowed(&post), None).await?;
        reject(state, path, &borrowed(&password_fields(path, BASIC)), None).await?;
        reject(
            state,
            path,
            &borrowed(&password_fields(path, PUBLIC)),
            Some(&basic()),
        )
        .await?;
        for extra in [
            vec![("client_assertion", "malformed")],
            vec![("client_assertion_type", ASSERTION_TYPE)],
            vec![("client_assertion", " ")],
            vec![("client_assertion_type", " ")],
        ] {
            let mut fields = password_fields(path, CLIENT);
            fields.extend(extra.into_iter().map(|(k, v)| (k.into(), v.into())));
            reject(state, path, &borrowed(&fields), None).await?;
        }
        let before = redis_keys(state)?;
        let mut ordinary = password_fields(path, BASIC);
        ordinary.push(("client_secret".into(), SECRET.into()));
        reject_request(state, path, &borrowed(&ordinary), Some(&basic())).await?;
        assert!(
            before == redis_keys(state)?,
            "ordinary mixture mutated scoped Redis keys"
        );
        ordinary.last_mut().ok_or("secret")?.1 = " ".into();
        reject_request(state, path, &borrowed(&ordinary), Some(&basic())).await?;
    }
    Ok(())
}

pub(super) async fn successful_response(
    state: &AppState,
    path: &str,
    fields: &[(&str, &str)],
    auth: Option<&str>,
) -> TestResult<Value> {
    let mut fields = fields.to_vec();
    if path == "/par" {
        fields.push(("iss", state.issuer.as_str()));
    }
    let (status, headers, body) =
        send_response(state, path, &serde_urlencoded::to_string(fields)?, auth).await?;
    assert_eq!(
        status,
        if path == "/par" {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        "{path}: {body}"
    );
    assert_client_challenge(path, &headers, false)?;
    match path {
        "/token" => assert!(body["access_token"].is_string()),
        "/device_authorization" => assert!(body["device_code"].is_string()),
        "/par" => assert!(body["request_uri"].is_string()),
        "/introspect" => assert_eq!(body["active"], false),
        "/revoke" => assert!(body.is_null()),
        _ => unreachable!(),
    }
    Ok(body)
}

async fn mixtures_preserve_assertion(state: &AppState) -> TestResult {
    for path in PATHS {
        for (with_basic, with_post) in [(true, false), (false, true), (true, true)] {
            let jwt = sign(&claims(state, path)?)?;
            let mut mixed = fields(path, &jwt);
            if with_post {
                mixed.push(("client_secret", SECRET));
            }
            let auth = basic();
            let before = redis_keys(state)?;
            reject(state, path, &mixed, with_basic.then_some(auth.as_str())).await?;
            assert!(
                before == redis_keys(state)?,
                "early mixture mutated scoped Redis keys"
            );
            successful_response(state, path, &fields(path, &jwt), None).await?;
            reject(state, path, &fields(path, &jwt), None).await?;
        }
    }
    Ok(())
}

async fn public_token(state: &AppState) -> TestResult {
    let request = serde_json::from_value(json!({"response_type":"code", "client_id":PUBLIC,
        "redirect_uri":REDIRECT,"scope":"api.read","code_challenge":CHALLENGE,"code_challenge_method":"S256"}))?;
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code(request, "auth-response-user".into())?;
    successful_response(
        state,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", PUBLIC),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
        None,
    )
    .await?;
    Ok(())
}

async fn controls(state: &AppState) -> TestResult {
    for path in PATHS {
        let mut fields = password_fields(path, BASIC);
        // Empty effective fields must not create another mechanism.
        fields.extend([
            ("client_secret".into(), "".into()),
            ("client_assertion".into(), "".into()),
            ("client_assertion_type".into(), "".into()),
        ]);
        successful_response(state, path, &borrowed(&fields), Some(&basic())).await?;
        let mut post = password_fields(path, POST);
        post.push(("client_secret".into(), SECRET.into()));
        successful_response(state, path, &borrowed(&post), None).await?;
        if path != "/token" {
            successful_response(state, path, &borrowed(&password_fields(path, PUBLIC)), None)
                .await?;
        }
    }
    public_token(state).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn recognized_client_authentication_errors_have_exact_challenges_and_preserve_replay(
) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        recognized_failures(&state).await?;
        controls(&state).await?;
        mixtures_preserve_assertion(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn profile_refusals(state: &AppState) -> TestResult {
    for path in PATHS {
        sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=$1 WHERE environment_id=$2")
            .bind(vec!["client_secret_basic", "client_secret_post", "none"])
            .bind(state.environment_id).execute(&state.db_pool).await?;
        let jwt = sign(&claims(state, path)?)?;
        let mut fields = fields(path, &jwt);
        if path == "/par" {
            fields.push(("iss", state.issuer.as_str()));
        }
        let before = state.device.code_store.try_active_count()?;
        let par_before = par_count(state)?;
        let (status, headers, body) =
            send_response(state, path, &serde_urlencoded::to_string(&fields)?, None).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}: {body}");
        assert_eq!(body["error"], "invalid_client");
        if path == "/device_authorization" {
            assert_eq!(headers.get_all(header::WWW_AUTHENTICATE).iter().count(), 1);
            assert_eq!(
                headers[header::WWW_AUTHENTICATE],
                "Basic realm=\"device_authorization\", error=\"invalid_client\""
            );
        } else {
            assert_client_challenge(path, &headers, true)?;
        }
        assert_eq!(state.device.code_store.try_active_count()?, before);
        assert_eq!(par_count(state)?, par_before);
        sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=$1 WHERE environment_id=$2")
            .bind(vec!["private_key_jwt", "client_secret_basic", "client_secret_post", "none"])
            .bind(state.environment_id).execute(&state.db_pool).await?;
        // Authentication consumed this assertion before the later profile refusal.
        reject(state, path, &fields, None).await?;
        let fresh = sign(&claims(state, path)?)?;
        successful_response(state, path, &super::fields(path, &fresh), None).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn client_profile_refusals_keep_challenges_and_authenticated_assertion_consumption(
) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async { profile_refusals(&fixture(&pool, &env).await?).await }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn revocation_owner_refusal_keeps_live_token_and_existing_client_challenge() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        let jwt = sign(&claims(&state, "/token")?)?;
        let issued = successful_response(&state, "/token", &fields("/token", &jwt), None).await?;
        let token = issued["access_token"].as_str().ok_or("token")?;
        reject(&state, "/revoke", &[("token", token)], Some(&basic())).await?;
        assert!(state.tokens.store.try_verify_access_token(token)?.is_some());
        super::success::authenticated_lifecycle(&state, token).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn jwt_introspection_without_requester_keeps_existing_client_challenge() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        update_test_policy(&mut state, |policy| policy.jwt_introspection_enabled = true).await?;
        let app = super::super::router::build_router(state).layer(Extension(ConnectInfo(
            SocketAddr::from(([127, 0, 0, 1], 12345)),
        )));
        let response = app
            .oneshot(
                Request::post("/introspect")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::ACCEPT, "application/token-introspection+jwt")
                    .body(Body::from("token=unknown-token"))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_client_challenge("/introspect", response.headers(), true)?;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "invalid_client");
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
