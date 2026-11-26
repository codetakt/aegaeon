//! Activation signs in the user. Password reset requires a subsequent sign-in.
use super::*;
use crate::local_credentials::{issue_recovery_token, RecoveryTokenPurpose};

const SUBJECT: &str = "recovery-route-user";
const RETURN_TO: &str = "/authorize?client_id=recovery-client&state=one%2Ftwo&prompt=consent";

async fn seed_token(
    pool: &PgPool,
    env: &TestEnvironment,
    purpose: RecoveryTokenPurpose,
) -> TestResult<crate::local_credentials::IssuedRecoveryToken> {
    let id = Uuid::new_v4();
    let status = match purpose {
        RecoveryTokenPurpose::Activation => "INVITED",
        RecoveryTokenPurpose::PasswordReset => "ACTIVE",
    };
    sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES ($1,$2,$3,$4::aegaeon.end_user_status)")
        .bind(id).bind(env.environment_id).bind(SUBJECT).bind(status).execute(pool).await?;
    if purpose == RecoveryTokenPurpose::PasswordReset {
        let previous_password = Uuid::new_v4().to_string();
        let hash = crate::local_credentials::hash_password(&previous_password)?;
        sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash) VALUES ($1,$2)")
            .bind(id).bind(hash).execute(pool).await?;
    }
    let mut tx = pool.begin().await?;
    let issued = issue_recovery_token(&mut tx, id, purpose, 300, None, None).await?;
    tx.commit().await?;
    Ok(issued)
}

async fn submit(
    browser: &mut Browser,
    state: &AppState,
    path: &str,
    token: &str,
    csrf: &str,
) -> TestResult<Page> {
    browser
        .request(
            state,
            path,
            Some(vec![
                ("token", token),
                ("password", PASSWORD),
                ("password_confirmation", PASSWORD),
                ("return_to", RETURN_TO),
                ("csrf_token", csrf),
            ]),
        )
        .await
}

async fn scenario(
    pool: &PgPool,
    env: &TestEnvironment,
    purpose: RecoveryTokenPurpose,
    ambient_session: bool,
) -> TestResult {
    let state = test_app_state(pool.clone(), env).await?;
    let issued = seed_token(pool, env, purpose).await?;
    let path = match purpose {
        RecoveryTokenPurpose::Activation => "/auth/activate",
        RecoveryTokenPurpose::PasswordReset => "/auth/password/reset",
    };
    let uri = format!(
        "{path}?{}",
        serde_urlencoded::to_string([("token", issued.token.as_str()), ("return_to", RETURN_TO)])?
    );
    let mut browser = Browser::default();
    if ambient_session {
        let sid = state
            .browser_auth
            .auth_sessions
            .create(
                SUBJECT,
                AuthSessionTimes::local(crate::util::now_unix_epoch_secs()?),
                None,
                None,
                None,
            )
            .ok_or("ambient session")?;
        browser
            .cookies
            .insert("aegaeon_auth_session".to_owned(), sid);
    }
    let original_sid = browser.cookies.get("aegaeon_auth_session").cloned();
    let sessions_before = state
        .browser_auth
        .auth_sessions
        .try_list_for_user(SUBJECT)?;
    let form = browser.request(&state, &uri, None).await?;
    assert_eq!(form.status, StatusCode::OK);
    assert_eq!(field(&form.body, "return_to")?, RETURN_TO);
    let csrf = field(&form.body, "csrf_token")?;
    let response = submit(&mut browser, &state, path, &issued.token, &csrf).await?;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert!(response.location.is_none());
    let destination = continuation_destination(&response.body)?;
    let sid = browser.cookies.get("aegaeon_auth_session").cloned();
    let sessions = state
        .browser_auth
        .auth_sessions
        .try_list_for_user(SUBJECT)?;
    match purpose {
        RecoveryTokenPurpose::Activation => {
            assert_eq!(destination, RETURN_TO);
            let sid = sid.as_ref().ok_or("activation session missing")?;
            assert_eq!(sessions.len(), 1);
            assert_eq!(&sessions[0].0, sid);
            assert_eq!(
                state
                    .browser_auth
                    .auth_sessions
                    .try_get(sid)?
                    .ok_or("issued session absent")?
                    .user_id,
                SUBJECT
            );
        }
        RecoveryTokenPurpose::PasswordReset => {
            assert_eq!(sid, original_sid);
            assert_eq!(sessions, sessions_before);
            assert!(destination.starts_with("/auth/login?"));
        }
    }
    let redeemed: bool = sqlx::query_scalar(
        "SELECT redeemed_at IS NOT NULL FROM aegaeon.end_user_recovery_tokens WHERE id=$1",
    )
    .bind(Uuid::parse_str(&issued.id)?)
    .fetch_one(pool)
    .await?;
    assert!(redeemed);

    // A new GET supplies fresh CSRF, so replay reaches token redemption.
    let replay_form = browser.request(&state, &uri, None).await?;
    assert_eq!(replay_form.status, StatusCode::OK);
    let fresh_csrf = field(&replay_form.body, "csrf_token")?;
    assert_ne!(fresh_csrf, csrf);
    let replay = submit(&mut browser, &state, path, &issued.token, &fresh_csrf).await?;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST, "{}", replay.body);
    assert!(replay
        .body
        .contains("The token is invalid, expired, or already used."));
    assert!(replay.location.is_none());
    assert!(!replay.body.contains("aegaeon-continuation"));
    assert_eq!(browser.cookies.get("aegaeon_auth_session"), sid.as_ref());
    assert_eq!(
        state
            .browser_auth
            .auth_sessions
            .try_list_for_user(SUBJECT)?,
        sessions
    );
    if purpose == RecoveryTokenPurpose::PasswordReset {
        let login_form = browser.request(&state, &destination, None).await?;
        assert_eq!(login_form.status, StatusCode::OK);
        let return_to = field(&login_form.body, "return_to")?;
        assert_eq!(return_to, RETURN_TO);
        let login_csrf = field(&login_form.body, "csrf_token")?;
        let signed_in = browser
            .request(
                &state,
                "/auth/login",
                Some(vec![
                    ("csrf_token", &login_csrf),
                    ("return_to", &return_to),
                    ("identifier", SUBJECT),
                    ("password", PASSWORD),
                ]),
            )
            .await?;
        assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.body);
        assert_eq!(continuation_destination(&signed_in.body)?, RETURN_TO);
        let fresh_sid = browser
            .cookies
            .get("aegaeon_auth_session")
            .ok_or("new session missing")?;
        assert_ne!(Some(fresh_sid), original_sid.as_ref());
        assert_eq!(
            state
                .browser_auth
                .auth_sessions
                .try_get(fresh_sid)?
                .ok_or("sign-in session absent")?
                .user_id,
            SUBJECT
        );
    }
    Ok(())
}

async fn cleanup_recovery_environment(
    pool: &PgPool,
    env: &TestEnvironment,
) -> Result<(), sqlx::Error> {
    // These credentials/tokens intentionally restrict deletion of their owner.
    sqlx::query("DELETE FROM aegaeon.end_user_recovery_tokens WHERE end_user_id IN (SELECT id FROM aegaeon.end_users WHERE environment_id=$1)")
        .bind(env.environment_id).execute(pool).await?;
    sqlx::query("DELETE FROM aegaeon.end_user_password_credentials WHERE end_user_id IN (SELECT id FROM aegaeon.end_users WHERE environment_id=$1)")
        .bind(env.environment_id).execute(pool).await?;
    cleanup_test_environment(pool, env).await
}

async fn run(purpose: RecoveryTokenPurpose, ambient_session: bool) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL required; no silent skip")?;
    let env = setup_test_environment(&pool).await?;
    let result = scenario(&pool, &env, purpose, ambient_session).await;
    finish_test(result, cleanup_recovery_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn activation_success_continues_locally_with_one_session_and_one_time_token() -> TestResult {
    run(RecoveryTokenPurpose::Activation, false).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn password_reset_requires_genuine_sign_in_to_resume() -> TestResult {
    run(RecoveryTokenPurpose::PasswordReset, false).await?;
    run(RecoveryTokenPurpose::PasswordReset, true).await
}
