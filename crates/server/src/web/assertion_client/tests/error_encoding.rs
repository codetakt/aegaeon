//! Router evidence: real PG registrations/profiles and Redis issuance stores.
use super::*;
use std::collections::BTreeSet;
const BAD_SCOPE: &str = "bad\"\\é雪😀\t";
const SCOPE_DETAIL: &str = "scope token `bad??????` is not a valid RFC 6749 scope-token";

fn scoped_keys(state: &AppState) -> TestResult<BTreeSet<String>> {
    let mut connection =
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?.get_connection()?;
    Ok(redis::cmd("KEYS")
        .arg(format!("aegaeon:{{runtime:{}:*", state.environment_id))
        .query(&mut connection)?)
}

async fn raw_request(
    state: &AppState,
    request: Request<Body>,
) -> TestResult<axum::response::Response> {
    Ok(crate::web::router::build_router(state.clone())
        .layer(Extension(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        )))))
        .oneshot(request)
        .await?)
}

async fn malformed_scopes(state: &AppState) -> TestResult {
    for path in ["/token", "/par", "/device_authorization"] {
        let mut pairs: Vec<_> = fields(path, "")
            .into_iter()
            .filter(|(name, _)| {
                !name.starts_with("client_assertion") && *name != "scope" && *name != "client_id"
            })
            .collect();
        pairs.extend([
            ("client_id", BASIC),
            ("scope", BAD_SCOPE),
            ("iss", state.issuer.as_str()),
        ]);
        // The client-credentials authority deliberately uses a fixed scope
        // error. A real JWT-bearer grant reaches the dynamic token scope parser.
        let grant_assertion;
        if path == "/token" {
            let mut grant_claims = claims(state, path)?;
            grant_claims["iss"] = json!(BASIC);
            grant_claims["sub"] = json!("encoding-user");
            grant_assertion = sign(&grant_claims)?;
            pairs.retain(|(name, _)| !matches!(*name, "grant_type" | "audience"));
            pairs.extend([
                ("grant_type", crate::policy::JWT_BEARER_GRANT_TYPE),
                ("assertion", grant_assertion.as_str()),
            ]);
        }
        let before = scoped_keys(state)?;
        let (status, headers, body) = send_response(
            state,
            path,
            &serde_urlencoded::to_string(&pairs)?,
            Some(&basic()),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(body["error"], "invalid_scope", "{path}");
        assert_eq!(body["error_description"], SCOPE_DETAIL, "{path}");
        assert!(!headers.contains_key(header::WWW_AUTHENTICATE));
        assert!(
            before == scoped_keys(state)?,
            "rejected scope created issuance records"
        );
        for name in [
            "code",
            "access_token",
            "refresh_token",
            "request_uri",
            "device_code",
        ] {
            assert!(body.get(name).is_none());
        }
        pairs.retain(|(name, _)| *name != "scope");
        pairs.push(("scope", "api.read"));
        let (status, body) = send(state, path, &pairs, Some(&basic())).await?;
        assert_eq!(
            status,
            if path == "/par" {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            }
        );
        assert!(body.get("error").is_none());
    }
    Ok(())
}

async fn authorize_scope(state: &mut AppState) -> TestResult {
    let sid = state
        .browser_auth
        .auth_sessions
        .create(
            "encoding-user",
            crate::web::AuthSessionTimes::local(crate::util::now_unix_epoch_secs()?),
            None,
            None,
            None,
        )
        .ok_or("session")?;
    for mode in ["json", "query", "form_post"] {
        update_test_policy(state, |policy| {
            policy.strict_authorize_redirect = mode != "json";
        })
        .await?;
        let pairs = [
            ("client_id", BASIC),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT),
            ("scope", BAD_SCOPE),
            ("state", "state-é&+"),
            ("iss", state.issuer.as_str()),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            (
                "response_mode",
                if mode == "form_post" {
                    "form_post"
                } else {
                    "query"
                },
            ),
        ];
        let before = scoped_keys(state)?;
        let response = raw_request(
            state,
            Request::get(format!(
                "/authorize?{}",
                serde_urlencoded::to_string(pairs)?
            ))
            .header(header::COOKIE, format!("aegaeon_auth_session={sid}"))
            .body(Body::empty())?,
        )
        .await?;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body: Value = match mode {
            "query" => {
                assert_eq!(response.status(), StatusCode::FOUND);
                let url = url::Url::parse(response.headers()[header::LOCATION].to_str()?)?;
                assert_eq!(
                    url.origin().ascii_serialization(),
                    "https://client.example.com"
                );
                assert_eq!(url.path(), "/callback");
                serde_json::to_value(
                    url.query_pairs()
                        .into_owned()
                        .collect::<std::collections::BTreeMap<_, _>>(),
                )?
            }
            "form_post" => {
                assert_eq!(response.status(), StatusCode::OK);
                let html =
                    String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?;
                assert!(html.contains(&format!("action=\"{REDIRECT}\"")));
                serde_json::to_value(crate::oauth_error::tests::decode_form(&html))?
            }
            _ => {
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?
            }
        };
        assert_eq!(body["error"], "invalid_scope");
        assert_eq!(body["error_description"], SCOPE_DETAIL);
        assert_eq!(body["state"], "state-é&+");
        assert_eq!(body["iss"], state.issuer.as_str());
        assert!(body.get("code").is_none());
        assert!(
            before == scoped_keys(state)?,
            "rejected authorize scope created records"
        );
    }
    Ok(())
}

async fn registration_scope(state: &AppState, pool: &sqlx::PgPool) -> TestResult {
    let count = || {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM aegaeon.dynamic_client_registrations WHERE environment_id=$1",
        )
        .bind(state.environment_id)
    };
    let before = count().fetch_one(pool).await?;
    let metadata = json!({"redirect_uris":[REDIRECT],"token_endpoint_auth_method":"none","grant_types":["authorization_code"],"response_types":["code"],"scope":BAD_SCOPE});
    let response = raw_request(
        state,
        Request::post("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&metadata)?))?,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(body["error"], "invalid_client_metadata");
    assert_eq!(
        body["error_description"],
        format!("scope is invalid: {SCOPE_DETAIL}")
    );
    assert!(body.get("client_id").is_none());
    assert_eq!(count().fetch_one(pool).await?, before);
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn oauth_error_encoding_scope_routes_preserve_issuance_and_registration_state() -> TestResult
{
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        malformed_scopes(&state).await?;
        authorize_scope(&mut state).await?;
        registration_scope(&state, &pool).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

fn upstream_request(
    state: &AppState,
    correlation: &str,
    browser_digest: &str,
) -> TestResult<crate::upstream::UpstreamAuthRequest> {
    let now = std::time::SystemTime::now();
    Ok(crate::upstream::UpstreamAuthRequest {
        state: correlation.into(),
        browser_binding_digest: Some(browser_digest.into()),
        nonce: "fixture".into(),
        code_verifier: None,
        acr: None,
        issuer: "https://upstream.example".into(),
        client_id: "upstream-client".into(),
        client_secret: None,
        client_auth_method: "none".into(),
        context: crate::upstream::UpstreamConnectionContext::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            state.environment_id,
            Uuid::new_v4(),
            Uuid::new_v4(),
        ),
        token_endpoint: "https://upstream.example/token".into(),
        jwks_uri: "https://upstream.example/jwks".into(),
        redirect_uri: crate::web::build_upstream_redirect_uri(&state.base_url, "fixture"),
        return_to: crate::web::validate_return_to(Some("/resume".into()))
            .map_err(std::io::Error::other)?,
        max_age: None,
        require_iss_parameter: true,
        jit_provisioning_policy: None,
        attribute_mappings: Vec::new(),
        claim_release_policy: None,
        logout_policy: None,
        issued_at: now,
        expires_at: now + std::time::Duration::from_secs(60),
    })
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn oauth_error_encoding_upstream_router_preserves_error_consumption_and_destination(
) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        for error in ["extension_error", "", "bad\"\\é"] {
            for redirect in [false, true] {
                let correlation = format!("{}-é&+", Uuid::new_v4());
                let secret = crate::upstream::random_token(32);
                let digest = aegaeon_crypto::hash::sha256_hex(secret.as_bytes());
                let cookie = format!(
                    "{}={secret}",
                    crate::web::upstream_browser_binding::cookie_name(&correlation)
                );
                let mut request = upstream_request(&state, &correlation, &digest)?;
                if !redirect {
                    request.return_to = None;
                }
                state
                    .upstream
                    .auth_store
                    .try_insert(request)
                    .map_err(std::io::Error::other)?;
                let before = scoped_keys(&state)?;
                let pairs = [
                    ("error", error),
                    ("error_description", BAD_SCOPE),
                    ("state", &correlation),
                    ("iss", "https://upstream.example"),
                ];
                let response = raw_request(
                    &state,
                    Request::get(format!(
                        "/oauth/upstream/fixture/callback?{}",
                        serde_urlencoded::to_string(pairs)?
                    ))
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())?,
                )
                .await?;
                let body: Value = if redirect {
                    assert_eq!(response.status(), StatusCode::FOUND);
                    let location = response.headers()[header::LOCATION].to_str()?;
                    assert!(location.starts_with("/resume?"));
                    let url = url::Url::parse(&format!("https://client.example{location}"))?;
                    let pairs: std::collections::BTreeMap<_, _> =
                        url.query_pairs().into_owned().collect();
                    assert_eq!(pairs["state"], correlation);
                    serde_json::to_value(pairs)?
                } else {
                    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?
                };
                assert_eq!(
                    body["error"],
                    if error == "extension_error" {
                        error
                    } else {
                        "server_error"
                    }
                );
                assert_eq!(body["error_description"], "bad??????");
                assert_eq!(body["iss"], state.issuer.as_str());
                assert!(state
                    .upstream
                    .auth_store
                    .try_consume_bound(
                        &correlation,
                        &digest,
                        &crate::web::build_upstream_redirect_uri(&state.base_url, "fixture"),
                    )
                    .map_err(std::io::Error::other)?
                    .is_none());
                assert!(
                    before == scoped_keys(&state)?,
                    "upstream error created issuance records"
                );
            }
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
