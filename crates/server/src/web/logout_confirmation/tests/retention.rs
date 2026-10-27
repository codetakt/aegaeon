use super::fixture::*;
use crate::web::{
    logout_confirmation::{storage, Browser},
    test_support::TestResult,
};
use axum::http::{Method, StatusCode};

async fn seed(f: &Fixture, count: i64, old: bool, expired: bool, decided: bool) -> TestResult {
    sqlx::query("INSERT INTO aegaeon.logout_confirmations(environment_id,issuer,token_sha256,browser_sha256,request_snapshot,created_at,expires_at,presented_at,decision,decided_at)
        SELECT $1,$2,gen_random_uuid()::text,'synthetic-binding','{}'::jsonb,
        now()-CASE WHEN $4 THEN interval '2 minutes' ELSE interval '0 seconds' END,
        now()+CASE WHEN $5 THEN interval '-1 second' ELSE interval '3 minutes' END,
        CASE WHEN $6 THEN now() END,CASE WHEN $6 THEN 'cancel' END,CASE WHEN $6 THEN now() END
        FROM generate_series(1,$3::bigint)")
        .bind(f.state.environment_id).bind(f.state.issuer.as_str()).bind(count).bind(old).bind(expired).bind(decided)
        .execute(&f.state.db_pool).await?;
    Ok(())
}
async fn clear(f: &Fixture) -> TestResult {
    sqlx::query("DELETE FROM aegaeon.logout_confirmations WHERE environment_id=$1")
        .bind(f.state.environment_id)
        .execute(&f.state.db_pool)
        .await?;
    Ok(())
}
fn error<T>(result: Result<T, axum::response::Response>) -> TestResult<StatusCode> {
    match result {
        Err(response) => Ok(response.status()),
        Ok(_) => Err("admission unexpectedly succeeded".into()),
    }
}

pub(super) async fn limits(f: &Fixture) -> TestResult {
    let mut state = f.state.clone();
    std::sync::Arc::make_mut(&mut state.cfg)
        .database
        .authorization_admission = crate::config::AuthorizationAdmissionLimits::new(7, 3, 1)?;
    let query = crate::web::logout_context::LogoutQuery::default();
    seed(f, 7, true, false, false).await?;
    assert_eq!(
        error(storage::create(&state, &query).await)?,
        StatusCode::TOO_MANY_REQUESTS
    );
    clear(f).await?;
    seed(f, 3, false, false, true).await?;
    assert_eq!(
        error(storage::create(&state, &query).await)?,
        StatusCode::TOO_MANY_REQUESTS,
        "consumed rows still use the admission budget"
    );
    sqlx::query("UPDATE aegaeon.logout_confirmations SET expires_at=now()-interval '1 second' WHERE environment_id=$1").bind(state.environment_id).execute(&state.db_pool).await?;
    let (token, secret) = storage::create(&state, &query)
        .await
        .map_err(|r| format!("create after prune {}", r.status()))?;
    let (a, b, c) = tokio::join!(
        storage::create(&state, &query),
        storage::create(&state, &query),
        storage::create(&state, &query)
    );
    assert_eq!(
        [a.is_ok(), b.is_ok(), c.is_ok()]
            .iter()
            .filter(|v| **v)
            .count(),
        2
    );
    let pending = storage::load(&state, &token, &secret)
        .await
        .map_err(|r| format!("load {}", r.status()))?;
    storage::present(&state, &pending, &Browser(None))
        .await
        .map_err(|r| format!("present {}", r.status()))?;
    storage::consume(&state, &pending, &Browser(None), &token, &secret, "cancel")
        .await
        .map_err(|r| format!("consume {}", r.status()))?;
    assert_eq!(
        error(storage::create(&state, &query).await)?,
        StatusCode::TOO_MANY_REQUESTS
    );
    clear(f).await?;
    seed(f, 513, true, true, false).await?;
    storage::create(&state, &query)
        .await
        .map_err(|r| format!("bounded prune {}", r.status()))?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.logout_confirmations WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .fetch_one(&state.db_pool)
    .await?;
    assert_eq!(
        count, 2,
        "one expired row remains after bounded 512-row prune"
    );
    assert_eq!(
        crate::web::authorization_transactions::cleanup_expired_authorization_transactions(
            &state.db_pool,
            state.environment_id
        )
        .await?,
        1
    );
    clear(f).await?;
    assert_eq!(
        send(&state, Method::GET, "/logout", None, None, "")
            .await?
            .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        send(&state, Method::GET, "/logout", None, None, "")
            .await?
            .status,
        StatusCode::TOO_MANY_REQUESTS,
        "shared Redis source limit"
    );
    Ok(())
}
