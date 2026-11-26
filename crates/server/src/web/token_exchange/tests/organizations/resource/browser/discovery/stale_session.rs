//! Use the ordinary password form and a single pushed, signed selection request.
use super::*;
use crate::web::authorization_consent_tests::{
    continuation_destination,
    reauthentication::{field, Browser},
};

const PASSWORD: &str = "organization-fresh-login-test-password";

async fn set_cutoff(f: &Fixture, cutoff: i64) -> TestResult {
    sqlx::query("UPDATE aegaeon.end_users SET organization_reauthentication_after=$2 WHERE id=$1")
        .bind(f.users[1])
        .bind(cutoff)
        .execute(&f.pool)
        .await?;
    Ok(())
}

async fn sign_in(
    browser: &mut Browser,
    state: &AppState,
    login: &str,
    subject: &str,
) -> TestResult<String> {
    let form = browser.request(state, login, None).await?;
    assert_eq!(form.status, StatusCode::OK, "{}", form.body);
    let csrf = field(&form.body, "csrf_token")?;
    let resume = field(&form.body, "return_to")?;
    let page = browser
        .request(
            state,
            "/auth/login",
            Some(vec![
                ("identifier", subject),
                ("password", PASSWORD),
                ("csrf_token", &csrf),
                ("return_to", &resume),
            ]),
        )
        .await?;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert_eq!(continuation_destination(&page.body)?, resume);
    Ok(resume)
}

async fn signed_selection(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
) -> TestResult<String> {
    let signed = request_objects::signed_selector(state, key)?;
    let (status, response) =
        request_objects::par(state, key, &[("client_id", OWNER), ("request", &signed)]).await?;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    Ok(format!(
        "/authorize?{}",
        serde_urlencoded::to_string([
            ("client_id", OWNER),
            (
                "request_uri",
                response["request_uri"].as_str().ok_or("PAR URI")?
            ),
        ])?
    ))
}

async fn same_second(f: &Fixture, state: &AppState) -> TestResult {
    let subject = format!("organization-user-{}", f.users[1]);
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let mut browser = Browser::default();
    browser.cookies.insert(
        "aegaeon_auth_session".into(),
        session(state, subject.clone()).await?,
    );
    let hash = crate::local_credentials::hash_password(PASSWORD)?;
    sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash) VALUES($1,$2)")
        .bind(f.users[1]).bind(hash).execute(&f.pool).await?;
    let initial = signed_selection(state, &key).await?;
    let page = browser.request(state, &initial, None).await?;
    assert_eq!(page.status, StatusCode::FOUND, "{}", page.body);
    let first = sign_in(
        &mut browser,
        state,
        &page.location.ok_or("sign-in redirect")?,
        &subject,
    )
    .await?;
    let sid = browser
        .cookies
        .get("aegaeon_auth_session")
        .ok_or("session cookie")?;
    let auth = state
        .browser_auth
        .auth_sessions
        .try_get_async(sid.clone())
        .await?
        .ok_or("login session")?;
    let cutoff = i64::try_from(auth.auth_time_epoch_secs)?;
    // Pin the independent primary cutoff to exactly the genuine issuer login time.
    set_cutoff(f, cutoff).await?;
    let original = browser.clone();
    let deadline = sqlx::query_scalar::<_, String>(
        "SELECT expires_at::text FROM aegaeon.authorization_logins WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .fetch_one(&f.pool)
    .await?;
    let mut rival = original.clone();
    let (a, b) = tokio::join!(
        browser.request(state, &first, None),
        rival.request(state, &first, None)
    );
    let (page, other) = match (a?, b?) {
        (page, other) if page.status == StatusCode::OK => (page, other),
        (other, page) => {
            browser = rival;
            (page, other)
        }
    };
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(other.status.is_client_error(), "{}", other.body);
    assert!(
        page.location.is_none()
            && !page.body.contains("http-equiv")
            && !page.body.contains("Select organization")
    );
    let manual = page
        .body
        .split("href=\"/auth/login?")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .ok_or("manual sign-in link")?;
    let login = format!("/auth/login?{}", manual.replace("&amp;", "&"));
    let deadlines = sqlx::query_scalar::<_, String>(
        "SELECT expires_at::text FROM aegaeon.authorization_logins WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .fetch_all(&f.pool)
    .await?;
    assert_eq!(deadlines, vec![deadline]);
    while i64::try_from(crate::util::now_unix_epoch_secs()?)? <= cutoff {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let second = sign_in(&mut browser, state, &login, &subject).await?;
    assert_ne!(first, second);
    let picker = browser.request(state, &second, None).await?;
    assert_eq!(picker.status, StatusCode::OK, "{}", picker.body);
    assert!(picker.body.contains(IDENTIFIER));
    let approval = browser
        .request(
            state,
            "/auth/consent",
            Some(vec![
                ("transaction", transaction(&picker.body)?),
                ("decision", "select:0"),
            ]),
        )
        .await?;
    let complete = browser
        .request(
            state,
            "/auth/consent",
            Some(vec![
                ("transaction", transaction(&approval.body)?),
                ("decision", "approve"),
            ]),
        )
        .await?;
    let grant = code(&complete.body, &state.issuer)?;
    redeem(state, &key, &grant).await?;
    assert!(browser
        .request(state, &second, None)
        .await?
        .status
        .is_client_error());
    assert!(browser
        .request(state, &initial, None)
        .await?
        .status
        .is_client_error());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_stale_session_preserves_single_use_signed_par() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let mut state = configured_discovery(&f).await?;
    request_objects::shared_request_stores(&mut state).await?;
    request_objects::register_request_key(&f).await?;
    let result = fixture::in_epoch(&state, Box::pin(same_second(&f, &state))).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

async fn stale_post(f: &Fixture, state: &AppState, at_approval: bool) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let subject = format!("organization-user-{}", f.users[1]);
    let sid = session(state, subject).await?;
    let auth = state
        .browser_auth
        .auth_sessions
        .try_get_async(sid.clone())
        .await?
        .ok_or("session")?;
    let mut browser = Browser::default();
    browser.cookies.insert("aegaeon_auth_session".into(), sid);
    let uri = selector_uri(state, &key)?;
    let picker = browser.request(state, &uri, None).await?;
    assert!(picker.body.contains(IDENTIFIER), "{}", picker.body);
    let (current, decision) = if at_approval {
        (
            browser
                .request(
                    state,
                    "/auth/consent",
                    Some(vec![
                        ("transaction", transaction(&picker.body)?),
                        ("decision", "select:0"),
                    ]),
                )
                .await?,
            "approve",
        )
    } else {
        (picker, "select:0")
    };
    set_cutoff(f, i64::try_from(auth.auth_time_epoch_secs)?).await?;
    let submit = vec![
        ("transaction", transaction(&current.body)?),
        ("decision", decision),
    ];
    let retry = browser
        .request(state, "/auth/consent", Some(submit.clone()))
        .await?;
    assert_eq!(retry.status, StatusCode::FOUND, "{}", retry.body);
    assert!(retry
        .location
        .as_deref()
        .is_some_and(|v| v.starts_with("/auth/login?")));
    assert!(browser
        .request(state, "/auth/consent", Some(submit))
        .await?
        .status
        .is_client_error());
    let snapshot: Value = sqlx::query_scalar(
        "SELECT request_snapshot FROM aegaeon.authorization_logins WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .fetch_one(&f.pool)
    .await?;
    assert_eq!(
        snapshot["request"]["authorization_details"][0]["selection"],
        "interactive"
    );
    assert!(snapshot.get("organization").is_none());
    assert_eq!(snapshot["reauthenticated"], false);
    let explicit = browser
        .request(state, &authorize(state, &key)?, None)
        .await?;
    assert_eq!(explicit.status, StatusCode::FOUND, "{}", explicit.body);
    assert!(explicit
        .location
        .as_deref()
        .is_some_and(|v| v.starts_with("/auth/login?")));

    sqlx::query("UPDATE aegaeon.end_users SET organization_identity_revision=9223372036854775807 WHERE id=$1")
        .bind(f.users[1]).execute(&f.pool).await?;
    scope_errors::authorize_error(
        state,
        &browser.cookies["aegaeon_auth_session"],
        &authorize(state, &key)?,
        "invalid_authorization_details",
    )
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_stale_picker_and_consent_discard_previous_decisions(
) -> TestResult {
    for at_approval in [false, true] {
        let f = Fixture::with_identifier(IDENTIFIER).await?;
        let state = configured_discovery(&f).await?;
        let result = fixture::in_epoch(&state, Box::pin(stale_post(&f, &state, at_approval))).await;
        fixture::finish(&state).await?;
        f.cleanup(result).await?;
    }
    Ok(())
}
