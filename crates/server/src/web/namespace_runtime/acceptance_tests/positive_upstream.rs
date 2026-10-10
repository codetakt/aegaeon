use super::{
    positive_support as p, positive_upstream_fixture as f,
    positive_upstream_observation as observation,
    positive_upstream_supplier::{Supplier, CLIENT, CODE},
    support::{unavailable, unavailable_states, TestResult},
};
use crate::web::AppState;
use axum::http::{header, StatusCode};
use std::collections::HashMap;

async fn authorize(state: &AppState, supplier: &Supplier) -> TestResult<String> {
    let path = format!(
        "/oauth/upstream/{}/authorize?return_to=%2Fnamespace-complete",
        f::CONNECTION
    );
    for denied in unavailable_states(state) {
        unavailable(p::send(&denied, "GET", &path, None, None, String::new()).await?).await?;
    }
    let response = p::send(state, "GET", &path, None, None, String::new()).await?;
    let response = p::status(response, StatusCode::FOUND).await?;
    let location = url::Url::parse(response.headers()[header::LOCATION].to_str()?)?;
    assert_eq!(location.origin().ascii_serialization(), supplier.endpoint);
    assert_eq!(location.path(), "/authorize");
    let query: HashMap<String, String> = location.query_pairs().into_owned().collect();
    assert_eq!(query.get("client_id").map(String::as_str), Some(CLIENT));
    assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(
        query.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    let state_token = query.get("state").ok_or("state")?.clone();
    assert!(!state_token.is_empty());
    let mut seen = supplier
        .observed
        .lock()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    seen.nonce = query.get("nonce").ok_or("nonce")?.clone();
    seen.redirect = query.get("redirect_uri").ok_or("redirect_uri")?.clone();
    seen.challenge = query.get("code_challenge").ok_or("code_challenge")?.clone();
    assert!(!seen.nonce.is_empty());
    assert_eq!(
        seen.redirect,
        format!("{}/oauth/upstream/{}/callback", state.issuer, f::CONNECTION)
    );
    Ok(state_token)
}

async fn scenario(
    state: AppState,
    supplier: Supplier,
    connection: uuid::Uuid,
    caller: String,
) -> TestResult {
    let state_token = authorize(&state, &supplier).await?;
    let path = format!(
        "/oauth/upstream/{}/callback?{}",
        f::CONNECTION,
        p::form(&[
            ("state", &state_token),
            ("code", CODE),
            ("iss", &supplier.issuer)
        ])
    );
    for denied in unavailable_states(&state) {
        unavailable(p::send(&denied, "GET", &path, None, None, String::new()).await?).await?;
    }
    let links: i64 =
        sqlx::query_scalar("SELECT count(*) FROM aegaeon.account_links WHERE environment_id=$1")
            .bind(state.environment_id)
            .fetch_one(&state.db_pool)
            .await?;
    assert_eq!(links, 0);
    assert_eq!(
        supplier
            .observed
            .lock()
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .code_exchanges,
        0
    );
    let response = p::send(&state, "GET", &path, None, None, String::new()).await?;
    let response = p::status(response, StatusCode::FOUND).await?;
    assert_eq!(response.headers()[header::LOCATION], "/namespace-complete");
    let cookie = response.headers()[header::SET_COOKIE].to_str()?;
    assert!(state
        .upstream
        .auth_store
        .try_consume(&state_token)?
        .is_none());
    let original = observation::assert_callback(&state, &supplier, connection, cookie).await?;
    observation::refresh(&state, &supplier, connection, original, &caller).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated restricted PostgreSQL and externally supplied AEGAEON_KEY_ENCRYPTION_KEY"]
async fn namespace_positive_upstream_authorize_callback_and_refresh_use_actual_supplier(
) -> TestResult {
    let supplier = Supplier::start().await?;
    let (state, connection, caller) = f::fixture(&supplier).await?;
    let handle = tokio::runtime::Handle::current();
    // Existing encryption fixtures share this lock. Build the DB runtime before acquiring it,
    // then retain the external key unchanged throughout callback/refresh encryption operations.
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
            .lock()
            .map_err(|e| e.to_string())?;
        crate::key_encryption::load_key_encryption_key().map_err(|error| format!("{error:?}"))?;
        handle
            .block_on(scenario(state, supplier, connection, caller))
            .map_err(|e| e.to_string())
    })
    .await?
    .map_err(std::io::Error::other)?;
    Ok(())
}
