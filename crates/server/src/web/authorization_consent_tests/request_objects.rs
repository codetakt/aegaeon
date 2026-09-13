use super::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
mod prompt_validation;
mod substitution;

pub(super) fn signed_request(state: &AppState, mode: &str) -> TestResult<String> {
    signed_request_with_prompt(state, mode, None)
}

fn signed_request_with_prompt(
    state: &AppState,
    mode: &str,
    prompt: Option<&str>,
) -> TestResult<String> {
    let now = crate::util::now_unix_epoch_secs()?;
    let mut claims = json!({
        "iss": CLIENT, "aud": state.issuer.as_str(), "client_id": CLIENT,
        "response_type": "code", "redirect_uri": "https://client.example.com/callback",
        "scope": SCOPE, "state": Uuid::new_v4().to_string(),
        "nonce": Uuid::new_v4().to_string(), "iat": now, "exp": now + 30,
        "jti": Uuid::new_v4().to_string(), "prompt": "consent",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method": "S256"
    });
    if mode.contains("login-consent") {
        claims["prompt"] = json!("login consent");
    } else if mode.contains("login") {
        claims["prompt"] = json!("login");
    }
    if mode.contains("zero-age") {
        claims["max_age"] = json!(0);
    }
    if mode.ends_with("no-prompt") {
        claims
            .as_object_mut()
            .ok_or("claims missing")?
            .remove("prompt");
    } else if mode.ends_with("wrong-audience") {
        claims["aud"] = json!("https://other-issuer.invalid");
    } else if mode.ends_with("endpoint-audience") {
        claims["aud"] = json!(format!("{}/authorize", state.issuer));
    } else if mode.ends_with("wrong-client") {
        claims["client_id"] = json!("different-client");
    } else if mode.ends_with("expired") {
        claims["iat"] = json!(now - 200);
        claims["exp"] = json!(now - 100);
    } else if mode.ends_with("bad-prompt") {
        claims["prompt"] = json!(["consent"]);
    } else if mode == "legacy-target" {
        // Negative upgrade fixture: the former adapter conflated these values.
        claims["iss"] = json!(state.issuer.as_str());
        claims["aud"] = json!(format!("{}/authorize", state.issuer));
    }
    if let Some(prompt) = prompt {
        claims["prompt"] = json!(prompt);
    }
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("oauth-authz-req+jwt".to_string());
    let jwt = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(include_bytes!(
            "../../../tests/fixtures/rsa2048-private.pk8.pem"
        ))?,
    )?;
    if mode.ends_with("bad-signature") {
        let (input, signature) = jwt.rsplit_once('.').ok_or("signature missing")?;
        let mut signature = URL_SAFE_NO_PAD.decode(signature)?;
        signature[0] ^= 1;
        return Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)));
    }
    Ok(jwt)
}

pub(super) async fn authorization_uri(
    state: &AppState,
    sid: &str,
    jwt: &str,
    mode: &str,
) -> TestResult<String> {
    if !mode.starts_with("par-") {
        let mut fields = vec![("client_id", CLIENT), ("request", jwt)];
        if mode.ends_with("outer-issuer") {
            fields.push(("iss", "https://unsigned.invalid"));
        }
        return Ok(format!(
            "/authorize?{}",
            serde_urlencoded::to_string(fields)?
        ));
    }
    let (status, body) = send(
        state,
        sid,
        "/par",
        Some(vec![("client_id", CLIENT), ("request", jwt)]),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let value: Value = serde_json::from_str(&body)?;
    let request_uri = value["request_uri"].as_str().ok_or("request_uri missing")?;
    Ok(format!(
        "/authorize?{}",
        serde_urlencoded::to_string([("client_id", CLIENT), ("request_uri", request_uri)])?
    ))
}

async fn rejected_request(state: &AppState, sid: &str, jwt: &str, mode: &str) -> TestResult {
    if mode == "par-outer-fields" {
        for (field, value) in [
            ("prompt", "consent"),
            ("iss", CLIENT),
            ("state", "unsigned"),
            ("scope", SCOPE),
            ("nonce", "unsigned"),
            ("response_mode", "query"),
            ("login_hint", "unsigned-user"),
        ] {
            let (status, body) = send(
                state,
                sid,
                "/par",
                Some(vec![
                    ("client_id", CLIENT),
                    ("request", jwt),
                    (field, value),
                ]),
                None,
            )
            .await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{field}: {body}");
            let response: Value = serde_json::from_str(&body)?;
            assert_eq!(response["error"], "invalid_request");
            assert!(
                response["error_description"]
                    .as_str()
                    .ok_or("description missing")?
                    .contains("outside request"),
                "{field}: {body}"
            );
        }
    } else {
        let uri = authorization_uri(state, sid, jwt, mode).await?;
        let (status, body) = send(state, sid, &uri, None, None).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(serde_json::from_str::<Value>(&body)?["error"].is_string());
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.authorization_consents WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .fetch_one(&state.db_pool)
    .await?;
    assert_eq!(count, 0, "rejected signed requests must not start consent");
    Ok(())
}

async fn run_signed(mode: &str) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, sid) = fixture(&pool, &env).await?;
        if mode == "par-redis" {
            shared_protocol_stores(&mut state)?;
        }
        let mut client = state.clients.try_get(CLIENT)?.ok_or("client missing")?;
        client.jwks_pem =
            Some(include_str!("../../../tests/fixtures/rsa2048-public.pem").to_string());
        assert!(state.clients.try_update(client)?);
        let jwt = signed_request(&state, mode)?;
        if mode == "legacy-target" {
            return legacy_pushed_target(&state, &sid, &jwt).await;
        }
        if [
            "wrong-audience",
            "endpoint-audience",
            "wrong-client",
            "expired",
            "bad-signature",
            "bad-prompt",
            "outer-fields",
        ]
        .iter()
        .any(|ending| mode.ends_with(ending))
        {
            return rejected_request(&state, &sid, &jwt, mode).await;
        }
        let uri = authorization_uri(&state, &sid, &jwt, mode).await?;
        let (status, body) = send(&state, &sid, &uri, None, None).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        if mode.ends_with("no-prompt") {
            assert!(redeem(&state, &sid, &body)
                .await?
                .get("refresh_token")
                .is_none());
        } else {
            complete_decision(
                &state,
                &sid,
                transaction(&body)?,
                if mode.ends_with("deny") {
                    "deny"
                } else {
                    "approve"
                },
            )
            .await?;
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn legacy_pushed_target(state: &AppState, sid: &str, jwt: &str) -> TestResult {
    // Reconstruct a record admitted under the former audience policy. The
    // current public /par endpoint must not be used to create legacy data.
    let claims = state
        .clients
        .verify_request_object(
            CLIENT,
            jwt,
            &format!("{}/authorize", state.issuer),
            state.cfg.crypto_profile,
        )?
        .claims;
    let mut stored = serde_json::to_value(&claims)?;
    stored["iss"] = json!(state.issuer.as_str());
    stored["prompt"] = json!("consent");
    stored["request_object"] = json!(jwt);
    stored["request_object_claims"] = serde_json::to_value(claims)?;
    let request: crate::par::ParRequest = serde_json::from_value(stored)?;
    let pushed = crate::par::process_par_request(&state.protocol.par_store, request)
        .map_err(|err| format!("legacy PAR fixture could not be stored: {}", err.error))?;
    let uri = format!(
        "/authorize?{}",
        serde_urlencoded::to_string([
            ("client_id", CLIENT),
            ("request_uri", pushed.request_uri.as_str())
        ])?
    );
    let (status, body) = send(state, sid, &uri, None, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(serde_json::from_str::<Value>(&body)?["error_description"]
        .as_str()
        .ok_or("description missing")?
        .contains("recipient binding"));
    Ok(())
}

fn shared_protocol_stores(state: &mut AppState) -> TestResult {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let par_store = Arc::new(
        crate::par::ParStore::try_new_from_shared_store_env_with_expires_in(90, &namespace)?,
    );
    let metrics = aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?;
    state.protocol.par_endpoint = Arc::new(crate::par::ParEndpoint::new(
        Arc::new(crate::metrics_integration::MetricsIntegration::new(
            Arc::new(metrics),
        )),
        par_store.clone(),
    ));
    state.protocol.par_store = par_store;
    let client = state.clients.try_get(CLIENT)?.ok_or("client missing")?;
    state
        .protocol
        .par_endpoint
        .register_client(crate::par::Client {
            client_id: CLIENT.to_string(),
            client_secret: None,
            token_endpoint_auth_method: "none".to_string(),
            redirect_uris: client.redirect_uris,
            allowed_scopes: client.allowed_scopes,
        });
    state.protocol.request_object_jti_store = Arc::new(
        crate::request_object_store::RequestObjectJtiStore::try_from_shared_store_env_with_ttl_secs(
            60, &namespace,
        )?,
    );
    let issuer = crate::authcode::TokenIssuer::try_from_shared_store_env_with_ttls(
        state.keys.access_token.clone(),
        300,
        3600,
        120,
        &namespace,
    )?
    .with_oidc(state.oidc.config.as_deref().cloned())
    .with_issuer(state.issuer.to_string())
    .with_jwt_access_tokens_enabled(true);
    state.tokens.store = Arc::new(issuer.token_store.clone());
    state.tokens.issuer = Arc::new(issuer);
    state.tokens.validator = Arc::new(
        crate::authcode::TokenValidator::with_policy(
            state.tokens.store.as_ref().clone(),
            state.keys.access_token.clone(),
            state.cfg.security_policy,
        )
        .with_jwt_access_tokens_enabled(true)
        .with_issuer(Some(state.issuer.to_string())),
    );
    Ok(())
}

macro_rules! signed_http_test {
    ($name:ident, $mode:literal) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL"]
        async fn $name() -> TestResult {
            run_signed($mode).await
        }
    };
}
signed_http_test!(offline_consent_http_jar_approve_refresh, "jar-approve");
signed_http_test!(offline_consent_http_jar_deny, "jar-deny");
signed_http_test!(offline_consent_http_jar_no_prompt, "jar-no-prompt");
signed_http_test!(
    offline_consent_http_jar_outer_issuer_is_not_target,
    "jar-outer-issuer"
);
signed_http_test!(
    offline_consent_http_jar_wrong_audience,
    "jar-wrong-audience"
);
signed_http_test!(
    offline_consent_http_jar_endpoint_audience_is_not_issuer,
    "jar-endpoint-audience"
);
signed_http_test!(offline_consent_http_jar_wrong_client, "jar-wrong-client");
signed_http_test!(offline_consent_http_jar_expired, "jar-expired");
signed_http_test!(offline_consent_http_jar_bad_signature, "jar-bad-signature");
signed_http_test!(offline_consent_http_jar_bad_prompt, "jar-bad-prompt");
signed_http_test!(offline_consent_http_par_jar_approve_refresh, "par-approve");
signed_http_test!(offline_consent_http_par_jar_deny, "par-deny");
signed_http_test!(offline_consent_http_par_jar_no_prompt, "par-no-prompt");
signed_http_test!(
    offline_consent_http_par_jar_legacy_target_is_rejected,
    "legacy-target"
);
signed_http_test!(
    offline_consent_http_par_jar_shared_redis_refresh,
    "par-redis"
);
signed_http_test!(
    offline_consent_http_par_jar_outer_authorization_fields,
    "par-outer-fields"
);
