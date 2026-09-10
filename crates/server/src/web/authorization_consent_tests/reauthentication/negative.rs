use super::*;

async fn begin(
    state: &AppState,
    sid: &str,
    mode: &str,
) -> TestResult<(Browser, String, String, String)> {
    let uri = request_uri(state, sid, mode).await?;
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".to_string(), sid.to_string());
    let page = browser.request(state, &uri, None).await?;
    assert_eq!(page.status, StatusCode::FOUND);
    let login = page.location.ok_or("login missing")?;
    let page = browser.request(state, &login, None).await?;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    Ok((
        browser,
        login,
        field(&page.body, "return_to")?,
        field(&page.body, "csrf_token")?,
    ))
}

async fn login(
    browser: &mut Browser,
    state: &AppState,
    uri: &str,
    csrf: &str,
    password: &str,
) -> TestResult<Page> {
    browser
        .request(
            state,
            "/auth/login",
            Some(vec![
                ("identifier", "consent-user"),
                ("password", password),
                ("return_to", uri),
                ("csrf_token", csrf),
            ]),
        )
        .await
}

async fn substitutions(
    state: &AppState,
    sid: &str,
    mode: &str,
    browser: &Browser,
    login_uri: &str,
    return_to: &str,
) -> TestResult {
    let page = Browser::default().request(state, login_uri, None).await?;
    assert_eq!(
        page.status,
        StatusCode::BAD_REQUEST,
        "foreign browser must not bind the form"
    );
    let (other, _, other_return, other_csrf) = begin(state, sid, mode).await?;
    let mut swapped = browser.clone();
    // Copy the actual CSRF cookie name from the other browser without its
    // separate authorization-login browser binding.
    for (name, value) in &other.cookies {
        if name.contains("csrf") {
            swapped.cookies.insert(name.clone(), value.clone());
        }
    }
    let page = login(&mut swapped, state, return_to, &other_csrf, PASSWORD).await?;
    assert_eq!(
        page.status,
        StatusCode::BAD_REQUEST,
        "CSRF from another request must not complete this request"
    );
    let token = url::form_urlencoded::parse(
        return_to
            .split_once('?')
            .ok_or("query missing")?
            .1
            .as_bytes(),
    )
    .find(|(k, _)| k == "aeg_login_continue")
    .ok_or("continuation missing")?
    .1
    .into_owned();
    let other_base = other_return
        .split("&aeg_login_continue=")
        .next()
        .ok_or("other URI missing")?;
    let swapped_uri = format!("{other_base}&aeg_login_continue={token}");
    let page = browser.clone().request(state, &swapped_uri, None).await?;
    assert_eq!(
        page.status,
        StatusCode::BAD_REQUEST,
        "another request cannot consume this receipt"
    );
    Ok(())
}

pub(super) async fn scenario(state: &AppState, sid: &str, mode: &str) -> TestResult {
    let (mut browser, login_uri, return_to, csrf) = begin(state, sid, mode).await?;
    substitutions(state, sid, mode, &browser, &login_uri, &return_to).await?;
    let pending = browser.clone().request(state, &return_to, None).await?;
    assert_eq!(
        pending.status,
        StatusCode::BAD_REQUEST,
        "pending challenge is not authentication"
    );
    let page = login(&mut browser, state, &return_to, &csrf, "wrong-password").await?;
    assert_eq!(page.status, StatusCode::UNAUTHORIZED, "{}", page.body);
    let csrf = field(&page.body, "csrf_token")?;
    let mut concurrent = browser.clone();
    let (left, right) = tokio::join!(
        login(&mut browser, state, &return_to, &csrf, PASSWORD),
        login(&mut concurrent, state, &return_to, &csrf, PASSWORD)
    );
    let (left, right) = (left?, right?);
    assert_eq!(
        usize::from(left.status == StatusCode::SEE_OTHER)
            + usize::from(right.status == StatusCode::SEE_OTHER),
        1
    );
    if right.status == StatusCode::SEE_OTHER {
        browser = concurrent;
    }
    let mut old_session = browser.clone();
    old_session
        .cookies
        .insert("aegaeon_auth_session".to_string(), sid.to_string());
    assert_eq!(
        old_session.request(state, &return_to, None).await?.status,
        StatusCode::BAD_REQUEST
    );
    let mut other_browser = browser.clone();
    other_browser.cookies.remove("aegaeon_authorization_login");
    assert_eq!(
        other_browser.request(state, &return_to, None).await?.status,
        StatusCode::BAD_REQUEST
    );
    let duplicate = format!("{return_to}&aeg_login_continue={}", "a".repeat(43));
    assert_eq!(
        browser
            .clone()
            .request(state, &duplicate, None)
            .await?
            .status,
        StatusCode::BAD_REQUEST
    );
    let mut concurrent = browser.clone();
    let (left, right) = tokio::join!(
        browser.request(state, &return_to, None),
        concurrent.request(state, &return_to, None)
    );
    let (left, right) = (left?, right?);
    assert_eq!(
        usize::from(left.status == StatusCode::OK) + usize::from(right.status == StatusCode::OK),
        1
    );
    let page = if left.status == StatusCode::OK {
        left
    } else {
        right
    };
    let consent = transaction(&page.body)?.to_string();
    let page = browser
        .request(
            state,
            "/auth/consent",
            Some(vec![("transaction", &consent), ("decision", "deny")]),
        )
        .await?;
    let value: Value = serde_json::from_str(&page.body)?;
    assert_eq!(value["error"], "access_denied");
    assert_eq!(
        browser.request(state, &return_to, None).await?.status,
        StatusCode::BAD_REQUEST
    );
    let page = browser
        .request(
            state,
            "/auth/consent",
            Some(vec![("transaction", &consent), ("decision", "approve")]),
        )
        .await?;
    assert_eq!(page.status, StatusCode::BAD_REQUEST);
    let (mut expired, login_uri, _, _) = begin(state, sid, mode).await?;
    sqlx::query("UPDATE aegaeon.authorization_logins SET expires_at=now()-interval '1 second' WHERE environment_id=$1")
        .bind(state.environment_id).execute(&state.db_pool).await?;
    assert_eq!(
        expired.request(state, &login_uri, None).await?.status,
        StatusCode::BAD_REQUEST
    );
    Ok(())
}
