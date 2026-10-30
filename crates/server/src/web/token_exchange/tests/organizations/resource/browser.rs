use super::*;

mod body_budget;
mod budget;

async fn page(
    state: &AppState,
    sid: &str,
    uri: &str,
    form: Option<&[(&str, &str)]>,
) -> TestResult<(StatusCode, String)> {
    let mut request = if form.is_some() {
        Request::post(uri)
    } else {
        Request::get(uri)
    };
    request = request.header(header::COOKIE, format!("aegaeon_auth_session={sid}"));
    let body = if let Some(form) = form {
        request = request
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, state.issuer.as_str());
        serde_urlencoded::to_string(form)?
    } else {
        String::new()
    };
    let mut request = request.body(Body::from(body))?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
    let response = crate::web::build_router(state.clone())
        .oneshot(request)
        .await?;
    let status = response.status();
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "{status} {uri}"
    );
    Ok((
        status,
        String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?,
    ))
}

async fn session(state: &AppState, subject: String) -> TestResult<String> {
    Ok(state
        .browser_auth
        .auth_sessions
        .try_create_async(
            subject,
            crate::web::AuthSessionTimes::local(crate::util::now_unix_epoch_secs()?),
            None,
            None,
            None,
        )
        .await?
        .ok_or("browser session missing")?)
}

fn authorize(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
) -> TestResult<String> {
    let signed = crate::web::test_support::native_dpop::proof(state, key, json!({}))?;
    let jkt = crate::util::compute_dpop_jkt_from_proof(&signed).ok_or("thumbprint")?;
    let details = json!([{"type":GRANT_TYPE,"locations":[format!("{}/organizations",state.issuer)],
        "organizations":[{"identifier":IDENTIFIER,"privileges":[PRIVILEGE]}]}])
    .to_string();
    Ok(format!(
        "/authorize?{}",
        serde_urlencoded::to_string([
            ("client_id", OWNER),
            ("response_type", "code"),
            ("redirect_uri", "https://example.test/cb"),
            ("scope", "read offline_access"),
            ("prompt", "consent"),
            ("state", "organization-browser"),
            ("iss", state.issuer.as_str()),
            ("resource", &format!("{}/userinfo", state.issuer)),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
            ),
            ("code_challenge_method", "S256"),
            ("dpop_jkt", &jkt),
            ("authorization_details", &details),
        ])?
    ))
}

fn transaction(html: &str) -> TestResult<&str> {
    html.split("name=\"transaction\" value=\"")
        .nth(1)
        .and_then(|v| v.split('"').next())
        .ok_or("consent transaction missing".into())
}

fn code(html: &str, issuer: &str) -> TestResult<String> {
    let target = html
        .split("id=\"aegaeon-continuation\" href=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .ok_or("browser continuation missing")?
        .replace("&amp;", "&");
    let url = url::Url::parse(&target)?;
    assert_eq!(url.origin().ascii_serialization(), "https://example.test");
    assert_eq!(url.path(), "/cb");
    let pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
    assert_eq!(
        pairs.get("state").map(|s| s.as_ref()),
        Some("organization-browser")
    );
    assert_eq!(pairs.get("iss").map(|s| s.as_ref()), Some(issuer));
    Ok(pairs
        .get("code")
        .ok_or("authorization code missing")?
        .to_string())
}

async fn configured(f: &Fixture) -> TestResult<AppState> {
    let mut state = setup(f).await?;
    let exchange = state.cfg.token_exchange.clone();
    crate::web::test_support::update_test_policy(&mut state, move |policy| {
        policy.allowed_grant_types = vec![
            "authorization_code".into(),
            "refresh_token".into(),
            TOKEN_EXCHANGE_GRANT_TYPE.into(),
        ];
        policy.jwt_access_tokens_enabled = true;
        policy.jwt_introspection_enabled = true;
        policy.authorization_details_types_supported = vec![
            GRANT_TYPE.into(),
            crate::organizations::ORGANIZATION_ACCESS_TYPE.into(),
        ];
        policy.token_exchange = exchange;
        policy.retain_refresh_chain = true;
        policy.enforce_refresh_sender_binding = true;
        policy.strict_authorize_redirect = true;
    })
    .await?;
    state.browser_auth.auth_sessions =
        Arc::new(crate::web::AuthSessionStore::try_from_management_policy(
            &crate::management::types::PolicyDocument::default(),
            &crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id),
        )?);
    super::super::super::use_redis_namespace(
        &mut state,
        &crate::config::RuntimeStateNamespace::from_environment_id(f.env.environment_id),
    )
    .await?;
    let rs: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2",
    )
    .bind(state.environment_id)
    .bind(RS)
    .fetch_one(&f.pool)
    .await?;
    sqlx::query("UPDATE aegaeon.authorization_domain_targets SET introspection_clients=$1 WHERE environment_id=$2 AND audience=$3")
        .bind(json!([{"clientRegistrationId":rs,"clientIdentifier":RS}]))
        .bind(state.environment_id).bind(format!("{}/organizations",state.issuer)).execute(&f.pool).await?;
    state.protocol.stepup_store = Arc::new(
        crate::stepup::StepUpStore::try_from_shared_store_env_with_ttl_secs(
            300,
            &crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id),
        )?,
    );
    state.device.local_login_rate_limiter = Arc::new(
        crate::device_authz::VerificationRateLimiter::try_from_shared_store_env(
            "AEGAEON_TEST_REDIS_URL",
            "local-login",
            &crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id),
        )?,
    );
    state.validate_subject_namespace().await?;
    Ok(state)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_browser_consent_to_resource_and_revocation() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured(&f).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let sid = session(&state,format!("organization-user-{}",f.users[1])).await?;
        let (status,html)=page(&state,&sid,&authorize(&state,&key)?,None).await?;
        assert_eq!(status,StatusCode::OK,"{html}");
        assert!(html.contains("Organization access") && html.contains(IDENTIFIER) && html.contains(PRIVILEGE),"{html}");
        let tx = transaction(&html)?;
        let form=[("transaction",tx),("decision","approve")];
        let (status,approved)=page(&state,&sid,"/auth/consent",Some(&form)).await?;
        assert_eq!(status,StatusCode::OK,"{approved}");
        let code=code(&approved,state.issuer.as_str())?;
        let signed=crate::web::test_support::native_dpop::proof(&state,&key,json!({}))?;
        let (status,parent)=http(&state,"/token",OWNER,&[
            ("grant_type","authorization_code"),("code",&code),("redirect_uri","https://example.test/cb"),("code_verifier",VERIFIER),
        ],Some(&signed),false).await?;
        assert_eq!(status,StatusCode::OK,"{parent}");
        let refresh=parent["refresh_token"].as_str().ok_or("refresh")?;
        let original = state.tokens.store.try_get_bearer_meta(parent["access_token"].as_str().ok_or("access")?)?.ok_or("original metadata")?;
        let signed=crate::web::test_support::native_dpop::proof(&state,&key,json!({}))?;
        let (status,parent)=http(&state,"/token",OWNER,&[
            ("grant_type","refresh_token"),("refresh_token",refresh),
        ],Some(&signed),false).await?;
        assert_eq!(status,StatusCode::OK,"refresh: {parent}");
        let renewed=state.tokens.store.try_get_bearer_meta(parent["access_token"].as_str().ok_or("renewed")?)?.ok_or("renewed metadata")?;
        assert_eq!(original.exchange_grant, renewed.exchange_grant,"original ceiling retained through refresh");
        assert_eq!(original.authorization_details, renewed.authorization_details);
        assert_ne!(page(&state,&sid,"/auth/consent",Some(&form)).await?.0,StatusCode::OK,"approval replay");
        let details=json!([{"type":crate::organizations::ORGANIZATION_ACCESS_TYPE,"identifier":IDENTIFIER,"privileges":[PRIVILEGE]}]).to_string();
        let audience=format!("{}/organizations",state.issuer);
        let signed=crate::web::test_support::native_dpop::proof(&state,&key,json!({}))?;
        let (status,selected)=http(&state,"/token",OWNER,&[
            ("grant_type",TOKEN_EXCHANGE_GRANT_TYPE),("subject_token",parent["access_token"].as_str().ok_or("access")?),
            ("subject_token_type","urn:ietf:params:oauth:token-type:access_token"),("audience",&audience),("authorization_details",&details),
        ],Some(&signed),false).await?;
        assert_eq!(status,StatusCode::OK,"{selected}");
        assert_eq!(selected["authorization_details"][0]["identifier"],IDENTIFIER);
        let token=selected["access_token"].as_str().ok_or("selected access")?;
        super::super::inspect(&state,token,RS,true).await?;
        super::super::inspect(&state,token,OWNER,false).await?;
        let auth=format!("DPoP {token}");
        let signed=super::proof(&state,&key,token,"GET",json!({}))?;
        assert_eq!(get(&state,Method::GET,PATH,Some(&auth),Some(&signed),"").await?.0,StatusCode::OK);
        sqlx::query("UPDATE aegaeon.authorization_domains SET enabled=false,revision=revision+1 WHERE id=$1")
            .bind(f.organization.scope.domain_id).execute(&f.pool).await?;
        let signed=super::proof(&state,&key,token,"GET",json!({}))?;
        assert_eq!(get(&state,Method::GET,PATH,Some(&auth),Some(&signed),"").await?.0,StatusCode::UNAUTHORIZED);
        super::super::inspect(&state,token,RS,false).await?;
        Ok(())
    }.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_browser_session_denial_stale_and_recovery() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured(&f).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let subject = format!("organization-user-{}",f.users[1]);
        let sid = session(&state,subject.clone()).await?;
        let other_sid = session(&state,subject).await?;
        let foreign_sid = session(&state,format!("organization-user-{}",f.users[0])).await?;
        let uri = authorize(&state,&key)?;
        let (status,html) = page(&state,&sid,&uri,None).await?;
        assert_eq!(status,StatusCode::OK,"{html}");
        let form = [("transaction",transaction(&html)?),("decision","approve")];
        for wrong_sid in [&other_sid,&foreign_sid] {
            assert_eq!(page(&state,wrong_sid,"/auth/consent",Some(&form)).await?.0,StatusCode::BAD_REQUEST);
        }
        let denied=[("transaction",transaction(&html)?),("decision","deny")];
        let (status,body)=page(&state,&sid,"/auth/consent",Some(&denied)).await?;
        assert_eq!(status,StatusCode::OK,"{body}");
        assert!(body.contains("access_denied") && code(&body,&state.issuer).is_err(),"{body}");
        assert_eq!(page(&state,&sid,"/auth/consent",Some(&form)).await?.0,StatusCode::BAD_REQUEST);
        let (status,html)=page(&state,&sid,&uri,None).await?;
        assert_eq!(status,StatusCode::OK,"{html}");
        let form=[("transaction",transaction(&html)?),("decision","approve")];
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET version=version+1 WHERE environment_id=$1 AND role_key='reader'")
            .bind(state.environment_id).execute(&f.pool).await?;
        let (status,body)=page(&state,&sid,"/auth/consent",Some(&form)).await?;
        assert_eq!(status,StatusCode::BAD_REQUEST,"stale role: {body}");
        assert!(!body.contains("aegaeon-continuation"));
        let (status,html)=page(&state,&sid,&uri,None).await?;
        assert_eq!(status,StatusCode::OK,"{html}");
        let form=[("transaction",transaction(&html)?),("decision","approve")];
        let mut unavailable=state.clone();
        unavailable.db_pool = sqlx::postgres::PgPoolOptions::new().max_connections(1)
            .connect_with((*state.db_pool.connect_options()).clone()).await?;
        unavailable.validate_subject_namespace().await?;
        unavailable.db_pool.close().await;
        assert_eq!(page(&unavailable,&sid,"/auth/consent",Some(&form)).await?.0,StatusCode::SERVICE_UNAVAILABLE);
        assert!(state.runtime_restart.is_requested(),"authority fault requests restart");
        assert_eq!(page(&state,&sid,"/auth/consent",Some(&form)).await?.0,StatusCode::SERVICE_UNAVAILABLE,"same runtime stays closed even with healthy pool");
        let mut restarted=test_app_state(f.pool.clone(),&f.env).await?;
        restarted.keys=state.keys.clone();
        restarted.browser_auth.auth_sessions=state.browser_auth.auth_sessions.clone();
        restarted.device.local_login_rate_limiter=state.device.local_login_rate_limiter.clone();
        restarted.protocol.stepup_store=state.protocol.stepup_store.clone();
        let namespace=crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
        super::super::super::use_redis_namespace(&mut restarted,&namespace).await?;
        crate::web::test_support::native_dpop::install(&mut restarted)?;
        restarted.validate_subject_namespace().await?;
        let (status,body)=page(&restarted,&sid,"/auth/consent",Some(&form)).await?;
        assert_eq!(status,StatusCode::OK,"new loaded runtime recovery: {body}");
        assert!(code(&body,&restarted.issuer).is_ok(),"{body}");
        fixture::finish(&restarted).await?;
        Ok(())
    }.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
