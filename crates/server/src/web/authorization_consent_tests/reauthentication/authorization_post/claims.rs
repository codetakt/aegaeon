use super::*;

pub(super) async fn snapshot(state: &AppState, return_to: &str) -> TestResult<Value> {
    let token = return_to
        .strip_prefix("/authorize?aeg_login_continue=")
        .ok_or("opaque")?;
    let hash = URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(token.as_bytes()));
    Ok(sqlx::query_scalar("SELECT request_snapshot FROM aegaeon.authorization_logins WHERE environment_id=$1 AND token_sha256=$2")
        .bind(state.environment_id).bind(hash).fetch_one(&state.db_pool).await?)
}

fn verified_claims(jwt: &str, jwks: &Value, issuer: &str, audience: &str) -> TestResult<Value> {
    let header = jsonwebtoken::decode_header(jwt)?;
    let jwk = jwks["keys"]
        .as_array()
        .ok_or("keys")?
        .iter()
        .find(|jwk| jwk["kid"].as_str() == header.kid.as_deref())
        .ok_or("key")?;
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk.clone())?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    Ok(jsonwebtoken::decode::<Value>(
        jwt,
        &jsonwebtoken::DecodingKey::from_jwk(&jwk)?,
        &validation,
    )?
    .claims)
}

pub(super) fn output(
    state: &AppState,
    page: &Page,
    tokens: &Value,
    saved: &Value,
    form_post: bool,
) -> TestResult {
    let req = &saved["request"];
    let returned_state = if form_post {
        field(&page.body, "state")?
    } else {
        url::Url::parse(page.location.as_deref().ok_or("redirect")?)?
            .query_pairs()
            .find(|(key, _)| key == "state")
            .ok_or("state")?
            .1
            .into_owned()
    };
    assert_eq!(returned_state, req["state"]);
    assert_eq!(tokens["scope"], req["scope"]);
    let id = verified_claims(
        tokens["id_token"].as_str().ok_or("ID token")?,
        &serde_json::to_value(state.oidc.config.as_ref().ok_or("OIDC")?.jwks())?,
        &state.issuer,
        CLIENT,
    )?;
    assert_eq!(id["nonce"], req["nonce"]);
    assert_eq!(id["sub"], "consent-user");
    let target = req["resource"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}/userinfo", state.issuer));
    let access = verified_claims(
        tokens["access_token"].as_str().ok_or("access token")?,
        &serde_json::json!({"keys":state.keys.access_token.jwt_signing_public_jwks()}),
        &state.issuer,
        &target,
    )?;
    assert_eq!(access["scope"], req["scope"]);
    assert_eq!(access["sub"], "consent-user");
    assert_eq!(access["client_id"], CLIENT);
    Ok(())
}

pub(super) async fn consent_snapshot(state: &AppState, token: &str, saved: &Value) -> TestResult {
    let hash = URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(token.as_bytes()));
    let current: Value = sqlx::query_scalar("SELECT request_snapshot FROM aegaeon.authorization_consents WHERE environment_id=$1 AND token_sha256=$2")
        .bind(state.environment_id).bind(hash).fetch_one(&state.db_pool).await?;
    for key in [
        "version",
        "input",
        "request",
        "prompt",
        "response_mode",
        "par_continuation",
    ] {
        assert_eq!(current[key], saved[key], "retained {key}");
    }
    assert_eq!(current["reauthenticated"], true);
    assert!(current["authentication_session"].is_object());
    Ok(())
}
