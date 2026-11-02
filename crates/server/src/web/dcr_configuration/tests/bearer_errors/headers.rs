use super::*;

#[derive(Clone, Copy)]
pub(super) enum Refusal {
    Bare,
    Malformed,
    Invalid,
}

pub(super) fn cases() -> TestResult<Vec<(HeaderMap, Refusal)>> {
    let mut cases = vec![(HeaderMap::new(), Refusal::Bare)];
    for (value, expected) in [
        ("", Refusal::Bare),
        (" \t ", Refusal::Bare),
        ("Basic private-sentinel", Refusal::Bare),
        ("Other private-sentinel extra", Refusal::Bare),
        ("Bearer", Refusal::Malformed),
        ("bEaReR \t", Refusal::Malformed),
        ("Bearer private-sentinel extra", Refusal::Malformed),
        ("Bearer private-sentinel", Refusal::Invalid),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value)?);
        cases.push((headers, expected));
    }
    let mut duplicate = bearer("private-sentinel")?;
    duplicate.append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Basic private-sentinel"),
    );
    cases.push((duplicate, Refusal::Malformed));
    let mut nontext = HeaderMap::new();
    nontext.insert(header::AUTHORIZATION, HeaderValue::from_bytes(&[0xff])?);
    cases.push((nontext, Refusal::Malformed));
    Ok(cases)
}

pub(super) async fn refusal(
    response: Response,
    expected: Refusal,
    head: bool,
    initial: bool,
    issuer: &str,
) -> TestResult {
    let (status, challenge, error) = match expected {
        Refusal::Bare => (StatusCode::UNAUTHORIZED, BARE_CHALLENGE, None),
        Refusal::Malformed => (
            StatusCode::BAD_REQUEST,
            REQUEST_CHALLENGE,
            Some("invalid_request"),
        ),
        Refusal::Invalid => (
            StatusCode::UNAUTHORIZED,
            TOKEN_CHALLENGE,
            Some("invalid_token"),
        ),
    };
    response_headers(&response, status, Some(challenge));
    if head || error.is_none() {
        return empty_body(response).await;
    }
    let body = json_error(
        response,
        error.ok_or_else(|| io::Error::other("missing expected error"))?,
        issuer,
    )
    .await?;
    let description = match expected {
        Refusal::Malformed => "malformed Authorization header",
        Refusal::Invalid if initial => "invalid initial access token",
        Refusal::Invalid => "invalid registration access token",
        Refusal::Bare => return Err(io::Error::other("unexpected bare response body").into()),
    };
    assert_eq!(body["error_description"], description);
    Ok(())
}

pub(super) async fn scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let state = protected_state(pool, env).await?;
    let app = crate::web::router::build_router(state.clone());
    let mut accepted = HeaderMap::new();
    accepted.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!(" \tbEaReR\t {INITIAL_TOKEN} \t"))?,
    );
    let (client, token) = create(&app, &accepted, &metadata()).await?;
    let active = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM aegaeon.client_secrets WHERE environment_id=$1 AND status='ACTIVE'",
    )
    .bind(env.environment_id)
    .fetch_one(pool)
    .await?;
    assert_eq!(active, 1);
    let before = state_digest(pool, env).await?;
    for (headers, expected) in cases()? {
        let response = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/register",
                &headers,
                &metadata().to_string(),
            )?)
            .await?;
        refusal(response, expected, false, true, &env.issuer_url).await?;
        for method in [Method::GET, Method::HEAD, Method::PUT, Method::DELETE] {
            let is_head = method == Method::HEAD;
            let response = app
                .clone()
                .oneshot(request(
                    method,
                    &format!("/register/{client}"),
                    &headers,
                    &metadata().to_string(),
                )?)
                .await?;
            refusal(response, expected, is_head, false, &env.issuer_url).await?;
        }
        assert_eq!(before, state_digest(pool, env).await?);
        owner_read(&app, &client, &token).await?;
    }
    role_and_owner_boundaries(pool, env, &app, &client, &token).await?;
    lifecycle(&app, env, &client, &token).await?;
    open_registration(state).await
}

async fn role_and_owner_boundaries(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    app: &axum::Router,
    client: &str,
    token: &str,
) -> TestResult {
    let (other, _) = create(app, &bearer(INITIAL_TOKEN)?, &metadata()).await?;
    let before = state_digest(pool, env).await?;
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/register",
            &bearer(token)?,
            &metadata().to_string(),
        )?)
        .await?;
    refusal(response, Refusal::Invalid, false, true, &env.issuer_url).await?;
    for (path, credential) in [
        (client, INITIAL_TOKEN),
        (other.as_str(), token),
        ("unknown-client", token),
    ] {
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            let response = app
                .clone()
                .oneshot(request(
                    method,
                    &format!("/register/{path}"),
                    &bearer(credential)?,
                    &metadata().to_string(),
                )?)
                .await?;
            refusal(response, Refusal::Invalid, false, false, &env.issuer_url).await?;
        }
    }
    let foreign = setup_test_dcr_environment(pool).await?;
    let result = async {
        let foreign_app = test_router(pool, &foreign).await?;
        let response = foreign_app
            .oneshot(request(
                Method::GET,
                &format!("/register/{client}"),
                &bearer(token)?,
                "",
            )?)
            .await?;
        refusal(
            response,
            Refusal::Invalid,
            false,
            false,
            &foreign.issuer_url,
        )
        .await
    }
    .await;
    finish_test(result, cleanup_test_dcr_environment(pool, &foreign).await)?;
    assert_eq!(before, state_digest(pool, env).await?);
    owner_read(app, client, token).await
}

async fn lifecycle(
    app: &axum::Router,
    env: &TestDcrEnvironment,
    client: &str,
    token: &str,
) -> TestResult {
    let path = format!("/register/{client}");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("bEaReR\t {token} \t"))?,
    );
    let response = app
        .clone()
        .oneshot(request(Method::HEAD, &path, &headers, "")?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    empty_body(response).await?;
    let mut value = metadata();
    value["client_id"] = json!(client);
    let response = app
        .clone()
        .oneshot(request(Method::PUT, &path, &headers, &value.to_string())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await?;
    assert_eq!(body["client_id"], client);
    let replacement = body["registration_access_token"]
        .as_str()
        .ok_or_else(|| io::Error::other("missing replacement token"))?;
    assert!(replacement != token);
    let response = app
        .clone()
        .oneshot(request(Method::GET, &path, &bearer(token)?, "")?)
        .await?;
    refusal(response, Refusal::Invalid, false, false, &env.issuer_url).await?;
    owner_read(app, client, replacement).await?;
    let response = app
        .clone()
        .oneshot(request(Method::DELETE, &path, &bearer(replacement)?, "")?)
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    empty_body(response).await?;
    let response = app
        .clone()
        .oneshot(request(Method::GET, &path, &bearer(replacement)?, "")?)
        .await?;
    refusal(response, Refusal::Invalid, false, false, &env.issuer_url).await
}

async fn open_registration(mut state: AppState) -> TestResult {
    state.dcr_required_bearer_hash = None;
    let app = crate::web::router::build_router(state);
    let mut value = metadata();
    value["token_endpoint_auth_method"] = json!("none");
    for (headers, _) in cases()? {
        create(&app, &headers, &value).await?;
    }
    Ok(())
}
