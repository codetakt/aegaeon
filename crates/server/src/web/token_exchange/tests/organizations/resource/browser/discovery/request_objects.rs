//! Real signed input and PAR remain immutable through both browser phases.
use super::*;

async fn shared_request_stores(state: &mut AppState) -> TestResult {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let store = Arc::new(
        crate::par::ParStore::try_new_from_shared_store_env_with_expires_in(90, &namespace)?,
    );
    state.protocol.request_object_jti_store = Arc::new(crate::request_object_store::RequestObjectJtiStore::try_from_shared_store_env_with_ttl_secs(60, &namespace)?);
    let metrics = aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?;
    state.protocol.par_endpoint = Arc::new(crate::par::ParEndpoint::new(
        Arc::new(crate::metrics_integration::MetricsIntegration::new(
            Arc::new(metrics),
        )),
        store.clone(),
    ));
    state.protocol.par_store = store;
    state.validate_subject_namespace().await?;
    Ok(())
}

async fn register_request_key(f: &Fixture) -> TestResult {
    let signing = crate::oidc::OidcSigningKey::from_rsa_pem(
        "organization-selector".into(),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa2048-private.pk8.pem"
        )),
    )?;
    sqlx::query("INSERT INTO aegaeon.dynamic_client_registrations(environment_id,client_id,client_identifier,registration_access_token_hash,client_id_issued_at,jwks) SELECT environment_id,id,client_identifier,repeat('a',64),statement_timestamp(),$1 FROM aegaeon.clients WHERE environment_id=$2 AND client_identifier=$3")
        .bind(serde_json::to_value(signing.jwks())?).bind(f.env.environment_id).bind(OWNER).execute(&f.pool).await?;
    Ok(())
}

fn signed_selector(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
) -> TestResult<String> {
    let uri = selector_uri(state, key)?;
    let fields: Vec<(String, String)> =
        serde_urlencoded::from_str(uri.split_once('?').ok_or("query")?.1)?;
    let mut claims = json!({});
    for (name, value) in fields {
        claims[&name] = if name == "authorization_details" {
            serde_json::from_str(&value)?
        } else {
            json!(value)
        };
    }
    let now = crate::util::now_unix_epoch_secs()?;
    claims["iss"] = json!(OWNER);
    claims["aud"] = json!(state.issuer.as_str());
    claims["iat"] = json!(now);
    claims["exp"] = json!(now + 30);
    claims["jti"] = json!(uuid::Uuid::new_v4().to_string());
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.typ = Some("oauth-authz-req+jwt".into());
    header.kid = Some("organization-selector".into());
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa2048-private.pk8.pem"
        )))?,
    )?)
}

async fn par(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    fields: &[(&str, &str)],
) -> TestResult<(StatusCode, Value)> {
    let signed = crate::web::test_support::native_dpop::proof(
        state,
        key,
        json!({"htu":format!("{}/par",state.issuer)}),
    )?;
    let mut request = Request::post("/par")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{OWNER}:{SECRET}"))),
        )
        .header("DPoP", signed)
        .body(Body::from(serde_urlencoded::to_string(fields)?))?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
    let response = crate::web::build_router(state.clone())
        .oneshot(request)
        .await?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    Ok((
        response.status(),
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?,
    ))
}

async fn reject_modified_signature(state: &AppState, sid: &str, signed: &str) -> TestResult {
    let parts: Vec<_> = signed.split('.').collect();
    let mut payload: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    payload["redirect_uri"] = json!("https://attacker.invalid/cb");
    let modified = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?),
        parts[2]
    );
    let uri = format!(
        "/authorize?{}",
        serde_urlencoded::to_string([("client_id", OWNER), ("request", modified.as_str())])?
    );
    let (status, body) = page(state, sid, &uri, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("invalid_request_object"), "{body}");
    Ok(())
}

async fn reject_replayed_grant(state: &AppState, sid: &str, uri: &str, pushed: bool) -> TestResult {
    let (_, replay) = page(state, sid, uri, None).await?;
    if pushed {
        assert!(
            !replay.contains("Select organization"),
            "consumed PAR reference"
        );
        return Ok(());
    }
    // Direct JAR replay is checked atomically with code issuance. Preparing a
    // fresh UI transaction does not reserve or grant the signed authorization.
    let (status, approval) = page(
        state,
        sid,
        "/auth/consent",
        Some(&[
            ("transaction", transaction(&replay)?),
            ("decision", "select:0"),
        ]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{approval}");
    let (_, rejected) = page(
        state,
        sid,
        "/auth/consent",
        Some(&[
            ("transaction", transaction(&approval)?),
            ("decision", "approve"),
        ]),
    )
    .await?;
    assert!(
        code(&rejected, &state.issuer).is_err(),
        "replayed JAR must never issue another code: {rejected}"
    );
    Ok(())
}

async fn journey(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    sid: &str,
    pushed: bool,
) -> TestResult {
    let signed = signed_selector(state, key)?;
    reject_modified_signature(state, sid, &signed).await?;
    let uri = if pushed {
        assert_eq!(
            par(
                state,
                key,
                &[
                    ("client_id", OWNER),
                    ("request", &signed),
                    ("scope", "read")
                ]
            )
            .await?
            .0,
            StatusCode::BAD_REQUEST,
            "unsigned PAR fields"
        );
        let (status, result) =
            par(state, key, &[("client_id", OWNER), ("request", &signed)]).await?;
        assert_eq!(status, StatusCode::CREATED, "{result}");
        format!(
            "/authorize?{}",
            serde_urlencoded::to_string([
                ("client_id", OWNER),
                (
                    "request_uri",
                    result["request_uri"].as_str().ok_or("PAR reference")?
                )
            ])?
        )
    } else {
        let tampered = format!(
            "/authorize?{}",
            serde_urlencoded::to_string([
                ("client_id", OWNER),
                ("request", signed.as_str()),
                ("resource", "https://attacker.invalid/api")
            ])?
        );
        assert_eq!(
            page(state, sid, &tampered, None).await?.0,
            StatusCode::BAD_REQUEST,
            "unsigned JAR resource"
        );
        format!(
            "/authorize?{}",
            serde_urlencoded::to_string([
                ("client_id", OWNER),
                ("request", signed.as_str()),
                ("redirect_uri", "https://attacker.invalid/cb"),
            ])?
        )
    };
    let (status, picker) = page(state, sid, &uri, None).await?;
    assert_eq!(status, StatusCode::OK, "{picker}");
    assert!(picker.contains("Select organization"));
    let first:Value=sqlx::query_scalar("SELECT request_snapshot FROM aegaeon.authorization_consents WHERE environment_id=$1 AND decision IS NULL AND authorize_uri='/authorize/organization-selection' ORDER BY created_at DESC LIMIT 1")
        .bind(state.environment_id).fetch_one(&state.db_pool).await?;
    assert_eq!(
        first["authorization"]["request"]["redirect_uri"], "https://example.test/cb",
        "outer redirect must never replace signed input"
    );
    assert!(
        serde_json::to_string(&first["authorization"])?.contains(&signed),
        "original signed bytes retained"
    );
    let (status, approval) = page(
        state,
        sid,
        "/auth/consent",
        Some(&[
            ("transaction", transaction(&picker)?),
            ("decision", "select:0"),
        ]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{approval}");
    let second:Value=sqlx::query_scalar("SELECT request_snapshot FROM aegaeon.authorization_consents WHERE environment_id=$1 AND decision IS NULL AND authorize_uri='/authorize' ORDER BY created_at DESC LIMIT 1")
        .bind(state.environment_id).fetch_one(&state.db_pool).await?;
    assert_eq!(second["authorization"], first["authorization"]);
    let (status, approved) = page(
        state,
        sid,
        "/auth/consent",
        Some(&[
            ("transaction", transaction(&approval)?),
            ("decision", "approve"),
        ]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let tokens = redeem(state, key, &code(&approved, &state.issuer)?).await?;
    assert_eq!(tokens["authorization_details"][0]["type"], GRANT_TYPE);
    assert_eq!(
        tokens["authorization_details"][0]["organizations"][0]["identifier"],
        IDENTIFIER
    );
    reject_replayed_grant(state, sid, &uri, pushed).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_selector_jar_par_preserves_signed_input_and_rejects_substitution(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let mut state = configured_discovery(&f).await?;
    shared_request_stores(&mut state).await?;
    register_request_key(&f).await?;
    let result = fixture::in_epoch(
        &state,
        Box::pin(async {
            let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
            let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
            journey(&state, &key, &sid, false).await?;
            journey(&state, &key, &sid, true).await?;
            Ok(())
        }),
    )
    .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
