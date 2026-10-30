use super::{
    management_fixture::user,
    support::{fixture, remote, unavailable, unavailable_states, TestResult},
};
use crate::web;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    Form,
};

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_login_preserves_csrf_password_usage_and_sessions_until_matching_permit(
) -> TestResult {
    let (state, env) = fixture().await?;
    let (id, subject) = user(&state, &env).await?;
    let password = "namespace-test-password";
    let hash = crate::local_credentials::hash_password(password)?;
    sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash) VALUES($1,$2)")
        .bind(id).bind(hash).execute(&state.db_pool).await?;
    let csrf = state.device.local_auth_csrf_store.try_generate()?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{}={csrf}", web::LOCAL_AUTH_CSRF_COOKIE_NAME).parse()?,
    );
    let form = vec![
        ("csrf_token".into(), csrf.clone()),
        ("identifier".into(), subject.clone()),
        ("password".into(), password.into()),
    ];
    for denied in unavailable_states(&state) {
        unavailable(
            web::local_auth::local_login_post(
                State(denied),
                remote(),
                headers.clone(),
                Ok(Form(form.clone())),
            )
            .await,
        )
        .await?;
        assert!(state
            .browser_auth
            .auth_sessions
            .try_list_for_user(&subject)?
            .is_empty());
        let untouched: bool = sqlx::query_scalar("SELECT last_used_at IS NULL FROM aegaeon.end_user_password_credentials WHERE end_user_id=$1")
            .bind(id).fetch_one(&state.db_pool).await?;
        assert!(untouched);
    }
    let response =
        web::local_auth::local_login_post(State(state.clone()), remote(), headers, Ok(Form(form)))
            .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()[header::SET_COOKIE]
        .to_str()?
        .contains(web::AUTH_SESSION_COOKIE_NAME));
    assert_eq!(
        state
            .browser_auth
            .auth_sessions
            .try_list_for_user(&subject)?
            .len(),
        1
    );
    assert!(!state.device.local_auth_csrf_store.try_validate(&csrf)?);
    let used: bool = sqlx::query_scalar("SELECT last_used_at IS NOT NULL FROM aegaeon.end_user_password_credentials WHERE end_user_id=$1")
        .bind(id).fetch_one(&state.db_pool).await?;
    assert!(used);
    Ok(())
}
