use super::*;

async fn query_refusal(
    response: Response,
    challenge: bool,
    head: bool,
    issuer: &str,
) -> TestResult {
    response_headers(
        &response,
        StatusCode::BAD_REQUEST,
        challenge.then_some(REQUEST_CHALLENGE),
    );
    if head {
        return empty_body(response).await;
    }
    let body = json_error(response, "invalid_request", issuer).await?;
    assert_eq!(
        body["error_description"],
        "credentials or tokens must not be included in the request URI"
    );
    Ok(())
}

pub(super) async fn scenario(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    state: &AppState,
    client: &str,
    token: &str,
) -> TestResult {
    let app = crate::web::router::build_router(state.clone());
    let before = state_digest(pool, env).await?;
    for query in [
        "access_token=private-sentinel",
        "access_token=",
        "access_token",
        "a%63cess_token=private-sentinel",
        "ACCESS-TOKEN=private-sentinel",
        "%20access_token%20=private-sentinel",
        "client_secret=unused&access_token=",
    ] {
        for method in [
            Method::POST,
            Method::GET,
            Method::HEAD,
            Method::PUT,
            Method::DELETE,
        ] {
            let (path, credential) = if method == Method::POST {
                ("/register".into(), INITIAL_TOKEN)
            } else {
                (format!("/register/{client}"), token)
            };
            for headers in [HeaderMap::new(), bearer(credential)?] {
                let head = method == Method::HEAD;
                let response = app
                    .clone()
                    .oneshot(request(
                        method.clone(),
                        &format!("{path}?{query}"),
                        &headers,
                        &metadata().to_string(),
                    )?)
                    .await?;
                query_refusal(response, true, head, &env.issuer_url).await?;
            }
        }
    }
    for method in [Method::POST, Method::PUT] {
        let path = if method == Method::POST {
            "/register".into()
        } else {
            format!("/register/{client}")
        };
        let response = app
            .clone()
            .oneshot(request(
                method,
                &format!("{path}?access_token={token}"),
                &HeaderMap::new(),
                "{",
            )?)
            .await?;
        query_refusal(response, true, false, &env.issuer_url).await?;
    }
    negative_routes(&app, env, client).await?;
    generic_queries(&app, env, client).await?;
    open_and_disabled(state, env, client).await?;
    handler_only(state, env, client).await?;
    assert_eq!(before, state_digest(pool, env).await?);
    owner_read(&app, client, token).await
}

async fn negative_routes(app: &axum::Router, env: &TestDcrEnvironment, client: &str) -> TestResult {
    for (method, path) in [
        (Method::GET, "/health".into()),
        (Method::POST, "/token".into()),
        (Method::POST, "/register-extra".into()),
        (Method::GET, "/register/".into()),
        (Method::GET, format!("/register/{client}/extra")),
        (Method::GET, "/register".into()),
        (Method::POST, format!("/register/{client}")),
        (Method::PATCH, format!("/register/{client}")),
        (Method::OPTIONS, format!("/register/{client}")),
    ] {
        let response = app
            .clone()
            .oneshot(request(
                method,
                &format!("{path}?access_token="),
                &HeaderMap::new(),
                "",
            )?)
            .await?;
        query_refusal(response, false, false, &env.issuer_url).await?;
    }
    Ok(())
}

async fn generic_queries(app: &axum::Router, env: &TestDcrEnvironment, client: &str) -> TestResult {
    for query in [
        "client_secret=private-sentinel".into(),
        "registration_access_token=private-sentinel".into(),
        format!("{}=x", "k".repeat(65)),
        format!("value={}", "v".repeat(8193)),
        "x=1&".repeat(65),
        format!("access_token={}", "v".repeat(16385)),
    ] {
        for path in ["/register".into(), format!("/register/{client}")] {
            let response = app
                .clone()
                .oneshot(request(
                    Method::PUT,
                    &format!("{path}?{query}"),
                    &HeaderMap::new(),
                    "",
                )?)
                .await?;
            response_headers(&response, StatusCode::BAD_REQUEST, None);
            json_error(response, "invalid_request", &env.issuer_url).await?;
        }
    }
    Ok(())
}

async fn open_and_disabled(state: &AppState, env: &TestDcrEnvironment, client: &str) -> TestResult {
    let mut open = state.clone();
    open.dcr_required_bearer_hash = None;
    let app = crate::web::router::build_router(open);
    let response = app
        .oneshot(request(
            Method::POST,
            "/register?access_token=",
            &HeaderMap::new(),
            "",
        )?)
        .await?;
    query_refusal(response, false, false, &env.issuer_url).await?;
    let mut disabled = state.clone();
    disabled.dcr_enabled = false;
    let app = crate::web::router::build_router(disabled);
    for (method, path) in [
        (Method::POST, "/register".into()),
        (Method::GET, format!("/register/{client}")),
    ] {
        let response = app
            .clone()
            .oneshot(request(method.clone(), &path, &HeaderMap::new(), "")?)
            .await?;
        response_headers(&response, StatusCode::NOT_FOUND, None);
        let response = app
            .clone()
            .oneshot(request(
                method,
                &format!("{path}?access_token="),
                &HeaderMap::new(),
                "",
            )?)
            .await?;
        query_refusal(response, false, false, &env.issuer_url).await?;
    }
    Ok(())
}

async fn handler_only(state: &AppState, env: &TestDcrEnvironment, client: &str) -> TestResult {
    use axum::extract::{OriginalUri, Path, State};
    let uri = format!("/register/{client}?access_token=").parse::<axum::http::Uri>()?;
    let response = crate::web::dcr_registration::register(
        State(state.clone()),
        OriginalUri("/register?access_token=".parse()?),
        HeaderMap::new(),
        axum::body::Bytes::new(),
    )
    .await;
    query_refusal(response, true, false, &env.issuer_url).await?;
    let response = crate::web::dcr_configuration::register_read(
        State(state.clone()),
        Path(client.to_owned()),
        OriginalUri(uri.clone()),
        HeaderMap::new(),
    )
    .await;
    query_refusal(response, true, false, &env.issuer_url).await?;
    let response = crate::web::dcr_configuration::register_update(
        State(state.clone()),
        Path(client.to_owned()),
        OriginalUri(uri.clone()),
        HeaderMap::new(),
        axum::body::Bytes::new(),
    )
    .await;
    query_refusal(response, true, false, &env.issuer_url).await?;
    let response = crate::web::dcr_configuration::register_delete(
        State(state.clone()),
        Path(client.to_owned()),
        OriginalUri(uri),
        HeaderMap::new(),
    )
    .await;
    query_refusal(response, true, false, &env.issuer_url).await
}
