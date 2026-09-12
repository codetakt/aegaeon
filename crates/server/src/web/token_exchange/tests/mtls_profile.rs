//! Real DB/Redis and HTTP handlers; certificates are asserted by a simulated
//! trusted terminator here. Actual TLS verification is exercised by release E2E.
use super::*;
use crate::config::TransportSecurityConfig;
use crate::middleware::tls::TransportSecurity;
use crate::policy::SenderConstraint;

async fn send(
    state: &AppState,
    path: &str,
    fields: &[(&str, &str)],
    access: Option<&str>,
    cert: Option<&str>,
    trusted: bool,
) -> TestResult<(StatusCode, Value)> {
    let remote = if trusted {
        [127, 0, 0, 3]
    } else {
        [127, 0, 0, 2]
    };
    let app = Router::new()
        .route("/token", post(crate::web::token_endpoint::token))
        .route(
            "/resource",
            axum::routing::get(crate::web::resource_endpoint::resource),
        )
        .route(
            "/browser-control",
            axum::routing::get(|| async { axum::Json(json!({"browser":"reachable"})) }),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::web::transport_boundary::transport_security_middleware,
        ))
        .layer(Extension(ConnectInfo(SocketAddr::from((remote, 12453)))))
        .with_state(state.clone());
    let mut request = if path == "/token" {
        Request::post(path)
    } else {
        Request::get(path)
    };
    request = request
        .header("x-forwarded-proto", "https")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if path == "/token" {
        request = request.header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{CLIENT}:{SECRET}"))),
        );
    } else if let Some(token) = access {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(cert) = cert {
        request = request.header("x-forwarded-client-cert", cert);
    }
    let response = app
        .oneshot(request.body(Body::from(serde_urlencoded::to_string(fields)?))?)
        .await?;
    let status = response.status();
    if path != "/browser-control" {
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        if path == "/resource" && status == StatusCode::UNAUTHORIZED {
            assert!(response.headers()[header::WWW_AUTHENTICATE]
                .to_str()?
                .contains("invalid_token"));
        }
    }
    Ok((
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?,
    ))
}

async fn scenarios(state: &AppState) -> TestResult {
    let a = format!("SHA256:{}", "AB".repeat(32));
    let b = format!("SHA256:{}", "CD".repeat(32));
    let audience = crate::resource_audience::protected_resource(state.issuer.as_str());
    let req = serde_json::from_value(json!({"response_type":"code","client_id":CLIENT,
        "redirect_uri":"https://client.example.com/callback","scope":SOURCE_SCOPE,"resource":audience,
        "state":uuid::Uuid::new_v4().to_string(),"code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}))?;
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code(req, "mtls-control".into())?;
    let code_fields = [
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT),
        ("code", code.as_str()),
        ("redirect_uri", "https://client.example.com/callback"),
        ("code_verifier", VERIFIER),
    ];
    let (status, _) = send(state, "/browser-control", &[], None, None, true).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "browser route must not require a certificate"
    );
    assert_eq!(
        send(state, "/token", &code_fields, None, Some(&a), false)
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(state, "/token", &code_fields, None, None, true)
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    let (status, initial) = send(state, "/token", &code_fields, None, Some(&a), true).await?;
    assert_eq!(status, StatusCode::OK, "mTLS code: {initial}");
    let refresh = initial["refresh_token"].as_str().ok_or("refresh")?;
    let token = initial["access_token"].as_str().ok_or("access")?;
    let (_, meta) = state
        .tokens
        .validator
        .validate_bearer_token_with_meta(&format!("Bearer {token}"))
        .map_err(|e| e.to_string())?;
    assert!(matches!(
        meta.ok_or("meta")?.sender_binding,
        Some(crate::authcode::types::SenderBinding::Mtls { .. })
    ));
    assert_eq!(initial["token_type"], "Bearer");
    assert_eq!(
        jwt(&initial)?["cnf"]["x5t#S256"],
        crate::middleware::tls::mtls_fingerprint_to_x5t_s256(&a).ok_or("fingerprint")?
    );
    for cert in [None, Some(b.as_str())] {
        let (status, body) = send(state, "/resource", &[], Some(token), cert, true).await?;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "wrong certificate: {body}"
        );
        assert_eq!(body["error"], "invalid_token");
        assert_eq!(
            send(state, "/resource", &[], Some(token), Some(&a), true)
                .await?
                .0,
            StatusCode::OK
        );
    }
    let fields = [
        ("grant_type", "refresh_token"),
        ("client_id", CLIENT),
        ("refresh_token", refresh),
    ];
    assert_eq!(
        send(state, "/token", &fields, None, Some(&b), true)
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    assert!(
        !state
            .tokens
            .store
            .try_get_refresh_token(refresh)?
            .ok_or("retained refresh")?
            .rotated
    );
    let (status, fresh) = send(state, "/token", &fields, None, Some(&a), true).await?;
    assert_eq!(status, StatusCode::OK, "mTLS refresh: {fresh}");
    assert_eq!(fresh["token_type"], "Bearer");
    assert_eq!(jwt(&fresh)?["cnf"], jwt(&initial)?["cnf"]);
    let mut subject = fresh["access_token"]
        .as_str()
        .ok_or("fresh access")?
        .to_string();
    for _ in 0..2 {
        let fields = [
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("client_id", CLIENT),
            ("subject_token", subject.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("audience", "internal-api"),
        ];
        assert_eq!(
            send(state, "/token", &fields, None, Some(&b), true)
                .await?
                .0,
            StatusCode::BAD_REQUEST
        );
        let (status, output) = send(state, "/token", &fields, None, Some(&a), true).await?;
        assert_eq!(status, StatusCode::OK, "mTLS exchange: {output}");
        assert_eq!(output["token_type"], "Bearer");
        assert_eq!(jwt(&output)?["cnf"], jwt(&initial)?["cnf"]);
        subject = output["access_token"]
            .as_str()
            .ok_or("exchanged access")?
            .to_string();
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn shared_redis_mtls_profile_preserves_binding_under_dpop_default() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        sqlx::query("UPDATE aegaeon.oauth_profiles SET sender_constrained = 'MTLS', enforce_refresh_sender_binding = true WHERE environment_id = $1")
            .bind(env.environment_id).execute(&pool).await?;
        let cfg = Arc::make_mut(&mut state.cfg);
        cfg.security_policy.sender_constrained = SenderConstraint::DPoP;
        cfg.mtls_enabled = true;
        let mut exchange = serde_json::to_value(&cfg.token_exchange)?;
        exchange["rules"][0]["sourceAudience"] = json!(crate::resource_audience::protected_resource(state.issuer.as_str()));
        cfg.token_exchange = serde_json::from_value(exchange)?;
        state.transport = TransportSecurity::new(TransportSecurityConfig { require_tls_proxy: true,
            trusted_proxies: vec!["127.0.0.3/32".parse()?], ..TransportSecurityConfig::default() });
        use_redis(&mut state)?;
        scenarios(&state).await
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
