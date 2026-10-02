use super::{
    positive_support as p,
    support::{fixture, unavailable, unavailable_states, TestResult},
};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn namespace_positive_dcr_create_returns_usable_registration_token() -> TestResult {
    let (state, _) = fixture().await?;
    let registration = json!({"redirect_uris":["https://client.example/callback"],
        "token_endpoint_auth_method":"none","grant_types":["authorization_code"],
        "response_types":["code"],"scope":"openid","pkce_required":true});
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM aegaeon.clients WHERE environment_id=$1")
            .bind(state.environment_id)
            .fetch_one(&state.db_pool)
            .await?;
    for denied in unavailable_states(&state) {
        unavailable(
            p::send(
                &denied,
                "POST",
                "/register",
                Some("application/json"),
                None,
                registration.to_string(),
            )
            .await?,
        )
        .await?;
    }
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM aegaeon.clients WHERE environment_id=$1")
            .bind(state.environment_id)
            .fetch_one(&state.db_pool)
            .await?;
    assert_eq!(before, after);
    let created = p::json(
        p::send(
            &state,
            "POST",
            "/register",
            Some("application/json"),
            None,
            registration.to_string(),
        )
        .await?,
        StatusCode::CREATED,
    )
    .await?;
    let client = created["client_id"].as_str().ok_or("client_id")?;
    let token = created["registration_access_token"]
        .as_str()
        .ok_or("registration token")?;
    assert!(!client.is_empty());
    assert!(!token.is_empty());
    let path = format!("/register/{client}");
    let authorization = format!("Bearer {token}");
    let read = p::json(
        p::send(
            &state,
            "GET",
            &path,
            None,
            Some(&authorization),
            String::new(),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(read["client_id"], client);
    assert_eq!(read["redirect_uris"], registration["redirect_uris"]);
    let persisted: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2 AND status='ACTIVE'")
        .bind(state.environment_id).bind(client).fetch_one(&state.db_pool).await?;
    assert_eq!(persisted, 1);
    Ok(())
}
