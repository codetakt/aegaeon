use super::{
    authorization_fixture::KEY,
    positive_support as p,
    support::{unavailable, unavailable_states, TestResult},
};
use crate::{
    management::types::{PolicyDocument, PolicySenderConstraint},
    web::{test_support as t, AppState},
};
use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

const CLIENT: &str = "namespace-positive-jwt-client";
const SECRET: &str = "namespace-positive-test-secret";
const GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

async fn fixture() -> TestResult<AppState> {
    let (pool, env) = p::pool_environment().await?;
    let policy = PolicyDocument {
        sender_constraint: PolicySenderConstraint::None,
        allowed_grant_types: vec!["authorization_code".into(), GRANT.into()],
        jwt_bearer_allow_client_subject: true,
        ..PolicyDocument::default()
    };
    sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document=jsonb_set(configuration_document,'{policy}',$1) WHERE environment_id=$2 AND status='ACTIVE'")
        .bind(serde_json::to_value(policy)?).bind(env.environment_id).execute(&pool).await?;
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1,token_endpoint_auth_methods_allowed=ARRAY['client_secret_basic'] WHERE environment_id=$2")
        .bind(vec!["authorization_code", GRANT]).bind(env.environment_id).execute(&pool).await?;
    let mut client = t::sample_registered_client(CLIENT);
    client.client_secret = Some(SECRET.into());
    client.token_endpoint_auth_method = "client_secret_basic".into();
    client.allowed_scopes = vec!["read".into()];
    client.allowed_grant_types = vec!["authorization_code".into(), GRANT.into()];
    let key = crate::oidc::OidcSigningKey::from_rsa_pem("namespace-positive-jwt".into(), KEY)?;
    client.inline_jwks = Some(
        crate::client_registry::RegisteredClientJwks::from_value(
            serde_json::to_value(key.jwks())?,
            false,
        )
        .map_err(std::io::Error::other)?,
    );
    crate::dcr_persistence::create_dynamic_registration(
        &pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        "namespace-jwt-registration",
        "namespace-jwt-fixture",
    )
    .await?;
    sqlx::query("INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES($1,'namespace-jwt-user','ACTIVE')")
        .bind(env.environment_id).execute(&pool).await?;
    p::bind_policy(t::test_app_state(pool, &env).await?).await
}

async fn issue(state: &AppState, subject: &str, audience: &str) -> TestResult {
    let now = crate::util::now_unix_epoch_secs()?;
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("namespace-positive-jwt".into());
    let assertion = jsonwebtoken::encode(
        &header,
        &json!({"iss":CLIENT,"sub":subject,"aud":audience,"iat":now,"exp":now+120,"jti":uuid::Uuid::new_v4().to_string()}),
        &EncodingKey::from_rsa_pem(KEY.as_bytes())?,
    )?;
    let body = p::form(&[
        ("grant_type", GRANT),
        ("assertion", &assertion),
        ("scope", "read"),
        ("resource", "https://resource.example/api"),
    ]);
    let auth = format!("Basic {}", STANDARD.encode(format!("{CLIENT}:{SECRET}")));
    for denied in unavailable_states(state) {
        unavailable(
            p::send(
                &denied,
                "POST",
                "/token",
                Some("application/x-www-form-urlencoded"),
                Some(&auth),
                body.clone(),
            )
            .await?,
        )
        .await?;
    }
    // The identical signed assertion must still be usable after both denied requests.
    let response = p::json(
        p::send(
            state,
            "POST",
            "/token",
            Some("application/x-www-form-urlencoded"),
            Some(&auth),
            body.clone(),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let token = response["access_token"].as_str().ok_or("access token")?;
    assert_eq!(response["token_type"], "Bearer");
    assert!(response.get("id_token").is_none());
    assert!(response.get("refresh_token").is_none());
    let meta = state
        .tokens
        .store
        .try_get_bearer_meta_async(token.to_owned())
        .await?
        .ok_or("persisted token")?;
    assert_eq!(meta.user_id, subject);
    assert_eq!(meta.client_id, CLIENT);
    assert_eq!(meta.audience, "https://resource.example/api");
    assert_eq!(meta.granted_scopes, vec!["read"]);
    let replay = p::json(
        p::send(
            state,
            "POST",
            "/token",
            Some("application/x-www-form-urlencoded"),
            Some(&auth),
            body,
        )
        .await?,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    assert_eq!(replay["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn namespace_positive_jwt_bearer_signed_assertions_preserve_subject_kind() -> TestResult {
    let state = fixture().await?;
    issue(
        &state,
        "namespace-jwt-user",
        &format!("{}/token", state.issuer),
    )
    .await?;
    // Existing client-subject policy requires the issuer audience, excluding /token.
    issue(&state, CLIENT, state.issuer.as_str()).await
}
