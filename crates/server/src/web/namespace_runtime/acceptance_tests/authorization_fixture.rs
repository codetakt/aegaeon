use super::{browser_consumption::session, support::TestResult};
use crate::{
    management::types::{PolicyDocument, PolicySenderConstraint},
    web::{test_support as t, AppState},
};
use axum::http::{header, HeaderMap};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

pub(super) const CLIENT: &str = "namespace-client";
pub(super) const KEY: &str = include_str!("../../../../tests/fixtures/rsa2048-private.pk8.pem");

pub(super) async fn fixture() -> TestResult<(AppState, String)> {
    let pool = t::test_pg_pool()
        .await?
        .ok_or("restricted PostgreSQL required")?;
    let env = t::setup_test_environment(&pool).await?;
    let mut client = t::sample_registered_client(CLIENT);
    client.allowed_scopes = vec!["openid".into(), "offline_access".into()];
    client.allowed_grant_types.push("refresh_token".into());
    let signing = crate::oidc::OidcSigningKey::from_rsa_pem("namespace-test".into(), KEY)?;
    client.inline_jwks = Some(
        crate::client_registry::RegisteredClientJwks::from_value(
            serde_json::to_value(signing.jwks())?,
            false,
        )
        .map_err(std::io::Error::other)?,
    );
    crate::dcr_persistence::create_dynamic_registration(
        &pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        "namespace-registration",
        "namespace-test",
    )
    .await?;
    let policy = PolicyDocument {
        sender_constraint: PolicySenderConstraint::None,
        strict_authorize_redirect: false,
        require_client_auth_par: false,
        // This fixture uses a registered public client; exercise its explicit revocation policy.
        require_client_auth_revocation: false,
        oidc_enabled: true,
        oidc_require_nonce: true,
        id_token_time_to_live_seconds: 300,
        ..PolicyDocument::default()
    };
    t::seed_oidc_configuration(&pool, &env, policy, "namespace-test").await?;
    let state = t::test_app_state(pool, &env).await?;
    state
        .protocol
        .par_endpoint
        .register_client(crate::par::Client {
            client_id: CLIENT.into(),
            client_secret: None,
            token_endpoint_auth_method: "none".into(),
            redirect_uris: client.redirect_uris,
            allowed_scopes: client.allowed_scopes,
        });
    let sid = session(&state, "namespace-user")?;
    assert!(state.require_subject_namespace().is_ok());
    Ok((state, sid))
}

pub(super) fn headers(state: &AppState, sid: &str) -> TestResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("aegaeon_auth_session={sid}").parse()?,
    );
    headers.insert(header::ORIGIN, state.issuer.parse()?);
    Ok(headers)
}

pub(super) fn signed_request(state: &AppState, jti: &str) -> TestResult<String> {
    let now = crate::util::now_unix_epoch_secs()?;
    let claims = json!({"iss":CLIENT,"aud":state.issuer.as_str(),"client_id":CLIENT,
        "response_type":"code","redirect_uri":"https://client.example.com/callback",
        "scope":"openid offline_access","state":uuid::Uuid::new_v4().to_string(),
        "nonce":uuid::Uuid::new_v4().to_string(),"iat":now,"exp":now+30,
        "jti":jti,"prompt":"consent",
        "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"});
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("oauth-authz-req+jwt".into());
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(KEY.as_bytes())?,
    )?)
}
