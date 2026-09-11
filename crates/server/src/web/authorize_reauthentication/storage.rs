use super::*;

fn one(count: u64) -> Result<(), Response> {
    if count == 1 {
        Ok(())
    } else {
        Err(invalid())
    }
}

pub(super) async fn create(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    uri: &str,
    token: &str,
    browser: &str,
) -> Result<(), Response> {
    let request_snapshot = snapshot(ctx)?;
    let mut tx = super::super::authorization_transactions::begin_with_limits(
        &state.db_pool,
        state.environment_id,
        super::super::authorization_transactions::Kind::Login,
        uri,
        &request_snapshot,
        &state.cfg.database.authorization_admission,
    )
    .await?;
    sqlx::query("INSERT INTO aegaeon.authorization_logins
        (environment_id,issuer,client_id,token_sha256,browser_sha256,authorize_uri,request_snapshot,created_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,statement_timestamp(),statement_timestamp()+interval '5 minutes')")
        .bind(state.environment_id).bind(state.issuer.as_str()).bind(&ctx.req.client_id)
        .bind(digest(token)).bind(digest(browser)).bind(uri).bind(request_snapshot)
        .execute(&mut *tx).await.map_err(|_| unavailable())?;
    tx.commit().await.map_err(|_| unavailable())?;
    Ok(())
}

pub(super) async fn bind_form(
    state: &AppState,
    token: &str,
    uri: &str,
    browser: &str,
    csrf: &str,
) -> Result<(), Response> {
    let count = sqlx::query(
        "UPDATE aegaeon.authorization_logins SET csrf_sha256=$1
        WHERE environment_id=$2 AND issuer=$3 AND token_sha256=$4 AND browser_sha256=$5
        AND authorize_uri=$6 AND completed_at IS NULL AND consumed_at IS NULL AND expires_at>now()",
    )
    .bind(digest(csrf))
    .bind(state.environment_id)
    .bind(state.issuer.as_str())
    .bind(digest(token))
    .bind(digest(browser))
    .bind(uri)
    .execute(&state.db_pool)
    .await
    .map_err(|_| unavailable())?
    .rows_affected();
    one(count)
}

pub(super) async fn complete(
    state: &AppState,
    token: &str,
    uri: &str,
    browser: &str,
    csrf: &str,
    session: &Value,
) -> Result<(), Response> {
    let count = sqlx::query(
        "UPDATE aegaeon.authorization_logins SET session_snapshot=$1,completed_at=now()
        WHERE environment_id=$2 AND issuer=$3 AND token_sha256=$4 AND browser_sha256=$5
        AND authorize_uri=$6 AND csrf_sha256=$7 AND completed_at IS NULL
        AND consumed_at IS NULL AND expires_at>now()",
    )
    .bind(session)
    .bind(state.environment_id)
    .bind(state.issuer.as_str())
    .bind(digest(token))
    .bind(digest(browser))
    .bind(uri)
    .bind(digest(csrf))
    .execute(&state.db_pool)
    .await
    .map_err(|_| unavailable())?
    .rows_affected();
    one(count)
}

pub(super) async fn consume(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    token: &str,
    uri: &str,
    browser: &str,
    session: &Value,
) -> Result<(), Response> {
    let count = sqlx::query(
        "UPDATE aegaeon.authorization_logins SET consumed_at=now()
        WHERE environment_id=$1 AND issuer=$2 AND client_id=$3 AND token_sha256=$4
        AND browser_sha256=$5 AND authorize_uri=$6 AND request_snapshot=$7 AND session_snapshot=$8
        AND completed_at IS NOT NULL AND consumed_at IS NULL AND expires_at>now()",
    )
    .bind(state.environment_id)
    .bind(state.issuer.as_str())
    .bind(&ctx.req.client_id)
    .bind(digest(token))
    .bind(digest(browser))
    .bind(uri)
    .bind(snapshot(ctx)?)
    .bind(session)
    .execute(&state.db_pool)
    .await
    .map_err(|_| unavailable())?
    .rows_affected();
    one(count)
}
