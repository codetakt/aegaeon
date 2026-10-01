//! Real context construction with the existing active-profile/client PG fixture.
mod observation;
use super::*;
use crate::client_registry::ClientRegistry;
use crate::management::types::PolicyDocument;
use crate::par::{ParRequest, StoredParRequest};
use crate::web::authorize_context::{build_authorize_request_context, AuthorizeRequestContext};
use crate::web::test_support::{derive_test_authorization_runtime, seed_oidc_configuration};
use crate::web::AppState;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use uuid::Uuid;

async fn context(
    state: &AppState,
    pairs: &[(String, String)],
) -> TestResult<AuthorizeRequestContext> {
    let query = serde_urlencoded::to_string(pairs)?;
    let uri = format!("/authorize?{query}").parse()?;
    match build_authorize_request_context(
        state,
        &uri,
        state.issuer.as_str(),
        "snapshot-input-test".to_string(),
    )
    .await
    {
        Ok(context) => Ok(context),
        Err(response) => {
            let status = response.status();
            let bytes = body::to_bytes(response.into_body(), 8192).await?;
            Err(io::Error::other(format!(
                "context rejected: {status}: {}",
                String::from_utf8_lossy(&bytes)
            ))
            .into())
        }
    }
}

fn plain_pairs(env: &TestDcrEnvironment, client: &RegisteredClient) -> Vec<(String, String)> {
    [
        ("state", "original-state"),
        ("response_type", "code"),
        ("client_id", client.client_id.as_str()),
        ("redirect_uri", client.redirect_uris[0].as_str()),
        ("iss", env.issuer_url.as_str()),
        ("scope", "openid"),
        ("resource", "https://resource.example/"),
        ("code_challenge", "original-challenge"),
        ("code_challenge_method", "S256"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn authorization_snapshot_preserves_plain_jar_par_resolution() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or_else(|| io::Error::other("AEGAEON_DATABASE_URL required; no silent skip"))?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let pem = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rsa2048-private.pk8.pem"
    ));
    let signing_key =
        crate::oidc::OidcSigningKey::from_rsa_pem("snapshot-input-test".to_string(), pem)?;
    let mut client = sample_registered_client("snapshot-input-client");
    client.inline_jwks = Some(
        crate::client_registry::RegisteredClientJwks::from_value(
            serde_json::to_value(signing_key.jwks())?,
            true,
        )
        .map_err(io::Error::other)?,
    );
    create_test_registration(pool, env, &client, "synthetic-snapshot-token").await?;
    let state = configured_state(pool, env, pem, &signing_key).await?;
    plain(&state, env, &client).await?;
    jar(&state, env, &client, pem).await?;
    par(&state, env, &client).await
}

async fn plain(
    state: &AppState,
    env: &TestDcrEnvironment,
    client: &RegisteredClient,
) -> TestResult {
    let pairs = plain_pairs(env, client);
    let context = context(state, &pairs).await?;
    assert_eq!(context.req.state.as_deref(), Some("original-state"));
    assert_eq!(
        context.req.resource.as_deref(),
        Some("https://resource.example/")
    );
    assert!(context.req.request_object.is_none());
    assert!(context.req.request_uri.is_none());
    assert!(context.par_authorize_continuation.is_none());

    Ok(())
}

async fn jar(
    state: &AppState,
    env: &TestDcrEnvironment,
    client: &RegisteredClient,
    pem: &str,
) -> TestResult {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let claims = json!({
        "iss":env.issuer_url,"aud":env.issuer_url,
        "exp":now+45,"jti":"snapshot-original-jti","client_id":client.client_id,
        "redirect_uri":client.redirect_uris[0],"response_type":"code","scope":"openid",
        "state":"signed-state","nonce":"signed-nonce","code_challenge":"signed-challenge",
        "code_challenge_method":"S256","prompt":"login","response_mode":"form_post"
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("snapshot-input-test".to_string());
    let signed = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes())?,
    )?;
    let pairs = vec![
        ("client_id".to_string(), client.client_id.clone()),
        ("request".to_string(), signed.clone()),
    ];
    let context = context(state, &pairs).await?;
    assert_eq!(context.req.request_object.as_deref(), Some(signed.as_str()));
    let retained = context
        .req
        .request_object_claims
        .as_ref()
        .ok_or_else(|| io::Error::other("resolved claims missing"))?;
    assert_eq!(retained.exp, Some(now + 45));
    assert_eq!(retained.jti.as_deref(), Some("snapshot-original-jti"));
    assert_eq!(context.req.state.as_deref(), Some("signed-state"));
    assert!(context.prompt.contains("login"));
    assert!(matches!(
        context.response_mode,
        crate::form_post::ResponseMode::FormPost
    ));
    assert!(context.par_authorize_continuation.is_none());

    Ok(())
}

async fn par(state: &AppState, env: &TestDcrEnvironment, client: &RegisteredClient) -> TestResult {
    let request_uri = crate::par::ParStore::generate_request_uri();
    let original_expiry = SystemTime::now() + Duration::from_secs(45);
    let request = ParRequest {
        client_id: client.client_id.clone(),
        redirect_uri: client.redirect_uris[0].clone(),
        response_type: "code".to_string(),
        iss: Some(env.issuer_url.clone()),
        resource: Some("https://resource.example/".to_string()),
        state: Some("pushed-state".to_string()),
        code_challenge: Some("pushed-challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        scope: Some("openid".to_string()),
        nonce: None,
        acr_values: None,
        prompt: None,
        max_age: None,
        authorization_details: None,
        client_secret: None,
        client_authenticated: true,
        request_object: None,
        request_object_claims: None,
    };
    state
        .protocol
        .par_store
        .insert_stored_request_for_test(
            &request_uri,
            StoredParRequest {
                client_id: client.client_id.clone(),
                request,
                expires_at: original_expiry,
                authorize_continuation: None,
            },
        )
        .map_err(io::Error::other)?;
    let pairs = vec![
        ("request_uri".to_string(), request_uri.clone()),
        ("client_id".to_string(), client.client_id.clone()),
    ];
    let context = context(state, &pairs).await?;
    assert_eq!(context.req.state.as_deref(), Some("pushed-state"));
    assert_eq!(
        context.req.request_uri.as_deref(),
        Some(request_uri.as_str())
    );
    let continuation = context
        .par_authorize_continuation
        .as_deref()
        .ok_or_else(|| io::Error::other("original continuation missing"))?;
    let resumed = crate::par::resume_authorize_with_par(
        state.protocol.par_store.as_ref(),
        &request_uri,
        &client.client_id,
        continuation,
    )
    .map_err(|error| io::Error::other(format!("resume: {error:?}")))?;
    assert_eq!(resumed.state, context.req.state);
    // A second initial reservation would fail. Successful context construction
    // above therefore checks that snapshot construction did not reserve twice.
    assert!(crate::par::reserve_authorize_with_par(
        state.protocol.par_store.as_ref(),
        &request_uri,
        &client.client_id
    )
    .is_err());
    assert!(original_expiry > SystemTime::now());
    Ok(())
}

async fn configured_state(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    _pem: &str,
    signing_key: &crate::oidc::OidcSigningKey,
) -> TestResult<AppState> {
    let policy = PolicyDocument {
        oidc_enabled: true,
        oidc_require_nonce: false,
        oidc_enable_logout: true,
        ..PolicyDocument::default()
    };
    seed_oidc_configuration(pool, env, policy, signing_key.kid()).await?;
    test_app_state(pool.clone(), env).await
}
