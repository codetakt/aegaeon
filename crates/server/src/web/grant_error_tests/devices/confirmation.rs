//! Real router, PostgreSQL configuration and Redis device/token state.
//! Browser sessions, CSRF tokens and verification rate limiting use the existing
//! process-local test stores; the browser never sends device client credentials.
use super::*;
mod admission;
mod rendering;

async fn browser_session(state: &AppState) -> TestResult<String> {
    Ok(state
        .browser_auth
        .auth_sessions
        .try_create(
            "grant-user",
            crate::web::AuthSessionTimes::local(crate::util::now_unix_epoch_secs()?),
            None,
            None,
            None,
        )?
        .ok_or("browser session")?)
}

async fn text(response: Response) -> TestResult<String> {
    Ok(String::from_utf8(
        to_bytes(response.into_body(), 65536).await?.to_vec(),
    )?)
}

fn csrf_cookie(response: &Response) -> TestResult<String> {
    Ok(response.headers()[header::SET_COOKIE]
        .to_str()?
        .split(';')
        .next()
        .ok_or("CSRF cookie")?
        .to_string())
}

async fn entry(state: &AppState, path: &str) -> TestResult<(String, String)> {
    let response = crate::web::router::build_router(state.clone())
        .oneshot(Request::builder().uri(path).body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    no_cache(&response);
    let cookie = csrf_cookie(&response)?;
    Ok((cookie, text(response).await?))
}

async fn browser_post(
    state: &AppState,
    path: &str,
    cookie: &str,
    sid: Option<&str>,
    fields: &[(&str, &str)],
) -> TestResult<Response> {
    let cookies = match sid {
        Some(sid) => format!("{cookie}; {}={sid}", crate::web::AUTH_SESSION_COOKIE_NAME),
        None => cookie.to_string(),
    };
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookies)
        .body(Body::from(form(fields)))?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43124))));
    Ok(crate::web::router::build_router(state.clone())
        .oneshot(request)
        .await?)
}

async fn action(
    state: &AppState,
    path: &str,
    sid: Option<&str>,
    code: &str,
    confirmations: &[&str],
) -> TestResult<Response> {
    let (cookie, _) = entry(state, "/device").await?;
    let csrf = cookie.split_once('=').ok_or("CSRF value")?.1;
    let mut fields = vec![("csrf_token", csrf), ("user_code", code)];
    fields.extend(confirmations.iter().map(|value| ("confirm_device", *value)));
    browser_post(state, path, &cookie, sid, &fields).await
}

async fn assert_issued_once(state: &AppState, code: &str) -> TestResult {
    let response = poll(state, OWNER, code).await?;
    assert_eq!(response.status(), StatusCode::OK);
    no_cache(&response);
    let issued = body(response).await?;
    let access = issued["access_token"]
        .as_str()
        .ok_or("actual access token")?;
    let saved = state
        .tokens
        .store
        .try_verify_access_token(access)?
        .ok_or("Redis token")?;
    assert_eq!(saved.client_id, OWNER);
    assert_eq!(saved.user_id, "grant-user");
    assert!(snapshot(state, code)?.is_empty());
    error(
        poll(state, OWNER, code).await?,
        StatusCode::BAD_REQUEST,
        "expired_token",
    )
    .await
}

async fn assert_page_error(response: Response, status: StatusCode) -> TestResult {
    assert_eq!(response.status(), status);
    no_cache(&response);
    let html = text(response).await?;
    assert!(!html.contains("Device Authorized"));
    assert!(!html.contains("access_token"));
    Ok(())
}
