use super::support::TestResult;
use crate::web::{self, test_support::TestEnvironment, AppState};
use axum::{body::Body, http::Request, response::Response};
use tower::ServiceExt;
use uuid::Uuid;

pub(super) async fn user(state: &AppState, env: &TestEnvironment) -> TestResult<(Uuid, String)> {
    let id = Uuid::new_v4();
    let subject = format!("namespace-{id}");
    sqlx::query(
        "INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')",
    )
    .bind(id)
    .bind(env.environment_id)
    .bind(&subject)
    .execute(&state.db_pool)
    .await?;
    Ok((id, subject))
}

fn router(state: &AppState) -> axum::Router {
    let mut configured = state.clone();
    std::sync::Arc::make_mut(&mut configured.management.cfg).allowed_origins =
        vec!["https://admin.example.com".into()];
    web::management::router(configured.management.clone()).with_state(configured)
}

pub(super) async fn human_session(state: &AppState, env: &TestEnvironment) -> TestResult<String> {
    let admin = Uuid::new_v4();
    let email = format!("namespace-{admin}@example.com");
    let password = "namespace-fixture-password";
    let hash = crate::local_credentials::hash_password(password)?;
    let mut tx = state.db_pool.begin().await?;
    sqlx::query(
        "INSERT INTO aegaeon.administrators(id,email,password_hash,kind) VALUES($1,$2,$3,'HUMAN')",
    )
    .bind(admin)
    .bind(&email)
    .bind(hash)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO aegaeon.team_memberships(team_id,administrator_id,role) VALUES($1,$2,'OWNER')",
    )
    .bind(env.team_id)
    .bind(admin)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/authentication/sessions")
                .extension(axum::extract::ConnectInfo(
                    "127.0.0.1:9000".parse::<std::net::SocketAddr>()?,
                ))
                .header("origin", "https://admin.example.com")
                .header("cookie", "csrf_token=namespace-csrf")
                .header("x-csrf-token", "namespace-csrf")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email":email,"password":password}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("aegaeon_admin_session="))
        .and_then(|v| v.split(';').next())
        .map(str::to_owned)
        .ok_or_else(|| "management login cookie missing".into())
}

pub(super) async fn request(
    state: &AppState,
    key: &str,
    method: &str,
    path: &str,
) -> TestResult<Response> {
    let app = router(state);
    Ok(app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("cookie", format!("{key}; csrf_token=namespace-csrf"))
                .header("origin", "https://admin.example.com")
                .header("x-csrf-token", "namespace-csrf")
                .header("content-type", "application/json")
                .body(Body::from("{}"))?,
        )
        .await?)
}

pub(super) fn base_path(env: &TestEnvironment, user: Uuid) -> String {
    format!(
        "/teams/{}/environments/{}/users/{user}",
        env.team_id, env.environment_id
    )
}

pub(super) async fn effects(state: &AppState, env: &TestEnvironment) -> TestResult<(i64, i64)> {
    let commands = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.management_user_runtime_commands WHERE environment_id=$1",
    )
    .bind(env.environment_id)
    .fetch_one(&state.db_pool)
    .await?;
    let audits = sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type LIKE 'management.user.%'")
        .bind(env.environment_id).fetch_one(&state.db_pool).await?;
    Ok((commands, audits))
}
