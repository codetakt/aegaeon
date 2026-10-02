//! Real token contexts and routed grants retain the authenticated registration.
use super::*;
use crate::web::token_endpoint::{build_token_context, snapshot_test_hook};

mod context;
mod failures;
mod refresh_seed;
mod routed;

const NEXT_SECRET: &str = "replacement-token-snapshot-secret";

async fn all_grants_fixture(pool: &sqlx::PgPool, env: &TestEnvironment) -> TestResult<AppState> {
    let mut state = fixture(pool, env).await?;
    let exchange = crate::policy::TOKEN_EXCHANGE_GRANT_TYPE;
    sqlx::query("UPDATE aegaeon.clients SET allowed_grant_types=array_append(allowed_grant_types,$1) WHERE environment_id=$2")
        .bind(exchange).bind(env.environment_id).execute(pool).await?;
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=array_append(allowed_grant_types,$1) WHERE environment_id=$2")
        .bind(exchange).bind(env.environment_id).execute(pool).await?;
    update_test_policy(&mut state, |policy| {
        policy.allowed_grant_types.push(exchange.into());
    })
    .await?;
    reload_clients(&state).await?;
    Ok(state)
}

async fn reload_clients(state: &AppState) -> TestResult {
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(&state.db_pool, state.clients.as_ref())
        .await?;
    Ok(())
}

async fn replace_client(state: &AppState) -> TestResult {
    // Change actual database input, then invoke the production projection loader.
    // No authentication result or policy decision is supplied by this fixture.
    let hash = crate::local_credentials::hash_password(NEXT_SECRET)?;
    let mut tx = state.db_pool.begin().await?;
    sqlx::query("UPDATE aegaeon.clients SET token_endpoint_authentication_method='client_secret_post', allowed_grant_types=ARRAY['client_credentials']::text[], allowed_scopes=ARRAY['other.read']::text[] WHERE environment_id=$1 AND client_identifier=$2")
        .bind(state.environment_id).bind(BASIC).execute(&mut *tx).await?;
    sqlx::query("UPDATE aegaeon.client_secrets SET secret_hash=$1 WHERE client_id IN (SELECT id FROM aegaeon.clients WHERE environment_id=$2 AND client_identifier=$3)")
        .bind(hash).bind(state.environment_id).bind(BASIC).execute(&mut *tx).await?;
    sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=NULL, jwks_uri='https://keys.example/new.json' WHERE client_id IN (SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2)")
        .bind(state.environment_id).bind(BASIC).execute(&mut *tx).await?;
    tx.commit().await?;
    reload_clients(state).await
}

async fn context(
    state: &AppState,
    grant: &str,
    auth: &str,
) -> Result<(crate::web::TokenEndpointContext, AppState), axum::response::Response> {
    let headers =
        HeaderMap::from_iter([(header::AUTHORIZATION, auth.parse().expect("fixture header"))]);
    build_token_context(
        state,
        &"/token".parse().expect("fixture URI"),
        &headers,
        vec![("grant_type".into(), grant.into())],
        state.issuer.as_str(),
        "snapshot-test".into(),
    )
    .await
}

mod dpop_minimum;
