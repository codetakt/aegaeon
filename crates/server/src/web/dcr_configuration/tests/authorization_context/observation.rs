//! Actual PG acquisition, real consumers and deterministic mutation boundaries.
use super::*;
use crate::runtime_authority::AuthorizationReadBarriers;
use std::sync::atomic::{AtomicUsize, Ordering};

const PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/rsa2048-private.pk8.pem"
));

async fn fixture(
    pool: &PgPool,
    env: &TestDcrEnvironment,
) -> TestResult<(AppState, RegisteredClient)> {
    let signing = crate::oidc::OidcSigningKey::from_rsa_pem("observed-key".into(), PEM)?;
    let mut client = sample_registered_client("observed-client");
    client.inline_jwks = Some(
        crate::client_registry::RegisteredClientJwks::from_value(
            serde_json::to_value(signing.jwks())?,
            true,
        )
        .map_err(io::Error::other)?,
    );
    create_test_registration(pool, env, &client, "synthetic-observation-token").await?;
    Ok((configured_state(pool, env, PEM, &signing).await?, client))
}

async fn required_pool() -> TestResult<PgPool> {
    test_pg_pool()
        .await?
        .ok_or_else(|| io::Error::other("AEGAEON_DATABASE_URL required; no silent skip").into())
}

fn barriers() -> AuthorizationReadBarriers {
    AuthorizationReadBarriers {
        observed: Arc::new(tokio::sync::Barrier::new(2)),
        resume: Arc::new(tokio::sync::Barrier::new(2)),
    }
}

async fn refused(state: &AppState, pairs: &[(String, String)]) -> TestResult<Response> {
    let uri = format!("/authorize?{}", serde_urlencoded::to_string(pairs)?).parse()?;
    build_authorize_request_context(
        state,
        &uri,
        state.issuer.as_str(),
        "negative-observation".into(),
    )
    .await
    .err()
    .ok_or_else(|| io::Error::other("expected context refusal").into())
}

fn location(response: &Response) -> TestResult<url::Url> {
    Ok(url::Url::parse(
        response
            .headers()
            .get(header::LOCATION)
            .ok_or_else(|| io::Error::other("expected safe redirect"))?
            .to_str()?,
    )?)
}

fn signed_pairs(
    env: &TestDcrEnvironment,
    client: &RegisteredClient,
) -> TestResult<Vec<(String, String)>> {
    signed_pairs_with_key(env, client, "observed-key", PEM)
}

fn signed_pairs_with_key(
    env: &TestDcrEnvironment,
    client: &RegisteredClient,
    kid: &str,
    pem: &str,
) -> TestResult<Vec<(String, String)>> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let claims = json!({"iss":env.issuer_url,"aud":env.issuer_url,"exp":now+45,"jti":"observed-jti",
        "client_id":client.client_id,"redirect_uri":client.redirect_uris[0],"response_type":"code","scope":"openid",
        "state":"signed-state","nonce":"signed-nonce","code_challenge":"signed-challenge-AAAAAAAAAAAAAAAAAAAAAAAAAA","code_challenge_method":"S256"});
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.into());
    let signed = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes())?,
    )?;
    Ok(vec![
        ("client_id".into(), client.client_id.clone()),
        ("request".into(), signed),
    ])
}

#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn selected_client_and_profile_share_actual_rr_under_concurrent_change() -> TestResult {
    let pool = required_pool().await?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = rr_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn rr_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    // Generate an ephemeral second key in memory; never persist private material.
    let second_pem = ephemeral_rsa_key()?;
    let (mut state, client) = fixture(pool, env).await?;
    let old_profile: Uuid = sqlx::query_scalar("UPDATE aegaeon.oauth_profiles SET expires_at=clock_timestamp()+interval '1 hour' WHERE environment_id=$1 RETURNING id")
        .bind(env.environment_id).fetch_one(pool).await?;
    let second =
        crate::oidc::OidcSigningKey::from_rsa_pem("replacement-key".into(), second_pem.as_str())?;
    let second_jwks = serde_json::to_value(second.jwks())?;
    let b = barriers();
    state.runtime_authority.authorization_read_barriers = Some(b.clone());
    let pairs = signed_pairs(env, &client)?;
    let mutation = async {
        b.observed.wait().await;
        let changed = async {
            let mut tx = pool.begin().await?;
            sqlx::query("UPDATE aegaeon.oauth_profiles SET is_default=false,expires_at=clock_timestamp()-interval '1 second' WHERE environment_id=$1")
                .bind(env.environment_id).execute(&mut *tx).await?;
            let replacement: Uuid = sqlx::query_scalar("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,require_pkce,require_state_parameter,require_iss_parameter,sender_constrained,enforce_refresh_sender_binding,allowed_grant_types,token_endpoint_auth_methods_allowed) SELECT environment_id,configuration_version_id,'replacement-default','DOWNSTREAM',true,true,false,false,'NONE',true,allowed_grant_types,token_endpoint_auth_methods_allowed FROM aegaeon.oauth_profiles WHERE id=$1 RETURNING id")
                .bind(old_profile).fetch_one(&mut *tx).await?;
            sqlx::query("UPDATE aegaeon.clients SET redirect_uris=ARRAY['https://changed.example/cb'],allowed_scopes=ARRAY['openid','changed'],oauth_profile_id=$1 WHERE environment_id=$2")
                .bind(replacement).bind(env.environment_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=$1 WHERE environment_id=$2")
                .bind(&second_jwks).bind(env.environment_id).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok::<Uuid, sqlx::Error>(replacement)
        }.await;
        b.resume.wait().await;
        changed
    };
    let (observed, changed) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(context(&state, &pairs), mutation)
    })
    .await?;
    let replacement = changed?;
    let observed = observed?;
    let selected = observed
        .observation
        .selected_clients
        .try_get(&client.client_id)?
        .ok_or_else(|| io::Error::other("selected client missing"))?;
    assert_eq!(selected.redirect_uris, client.redirect_uris);
    assert_eq!(selected.allowed_scopes, client.allowed_scopes);
    let profile = observed
        .observation
        .profile
        .as_ref()
        .ok_or_else(|| io::Error::other("selected profile missing"))?;
    assert_eq!(profile.id, old_profile.to_string());
    assert!(profile.require_iss_parameter);
    let original_jwks = serde_json::to_value(
        crate::oidc::OidcSigningKey::from_rsa_pem("observed-key".into(), PEM)?.jwks(),
    )?;
    assert_ne!(original_jwks["keys"][0]["n"], second_jwks["keys"][0]["n"]);
    state.runtime_authority.authorization_read_barriers = None;
    // A fresh snapshot rejects the original JAR against the replaced real key.
    assert_eq!(
        refused(&state, &pairs).await?.status(),
        StatusCode::BAD_REQUEST
    );
    let mut changed_client = client.clone();
    changed_client.redirect_uris = vec!["https://changed.example/cb".into()];
    let new_pairs =
        signed_pairs_with_key(env, &changed_client, "replacement-key", second_pem.as_str())?;
    let fresh = context(&state, &new_pairs).await?;
    assert_eq!(
        fresh.req.redirect_uri.as_deref(),
        Some("https://changed.example/cb")
    );
    let fresh_profile = fresh
        .observation
        .profile
        .as_ref()
        .ok_or_else(|| io::Error::other("replacement profile missing"))?;
    assert_eq!(fresh_profile.id, replacement.to_string());
    assert!(!fresh_profile.require_iss_parameter);
    // Removing the explicit binding selects the new default, not the retired
    // former default. Both choices use the real new JAR key.
    sqlx::query("UPDATE aegaeon.clients SET oauth_profile_id=NULL WHERE environment_id=$1")
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    let default = context(&state, &new_pairs).await?;
    assert_eq!(
        default.observation.profile.as_ref().map(|p| p.id.as_str()),
        Some(replacement.to_string()).as_deref()
    );
    sqlx::query("UPDATE aegaeon.oauth_profiles SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1").bind(replacement).execute(pool).await?;
    let response = refused(&state, &plain_pairs(env, &client)).await?;
    assert!(response.headers().get(header::LOCATION).is_none());
    assert_eq!(
        response_json(response).await?["error_description"],
        "oauth profile is required"
    );
    Ok(())
}

fn ephemeral_rsa_key() -> TestResult<String> {
    let generated = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        .output()?;
    if !generated.status.success() {
        return Err(io::Error::other("ephemeral RSA fixture generation failed").into());
    }
    Ok(String::from_utf8(generated.stdout)?)
}

#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn actual_route_error_uses_selected_redirect_after_registry_replacement() -> TestResult {
    let pool = required_pool().await?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = route_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn route_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let (mut state, client) = fixture(pool, env).await?;
    let b = barriers();
    state.runtime_authority.authorization_context_barriers = Some(b.clone());
    let registry = state.clients.clone();
    let app = crate::web::router::build_router(state);
    let mut pairs = plain_pairs(env, &client);
    pairs.push(("prompt".into(), "none".into()));
    let mut request = Request::builder()
        .uri(format!(
            "/authorize?{}",
            serde_urlencoded::to_string(&pairs)?
        ))
        .body(Body::empty())?;
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        ))));
    let mutation = async {
        b.observed.wait().await;
        let mut changed = client.clone();
        changed.redirect_uris = vec!["https://new.example/cb".into()];
        let result = registry.try_update(changed);
        b.resume.wait().await;
        result
    };
    let (response, changed) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(app.oneshot(request), mutation)
    })
    .await?;
    assert!(changed?);
    let redirect = location(&response?)?;
    assert!(redirect.as_str().starts_with(&client.redirect_uris[0]));
    assert!(redirect
        .query_pairs()
        .any(|(k, v)| k == "error" && v == "login_required"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn explicit_default_profile_errors_and_jar_error_order_are_preserved() -> TestResult {
    let pool = required_pool().await?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = profile_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn profile_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let (state, client) = fixture(pool, env).await?;
    let pairs = plain_pairs(env, &client);
    let initial = context(&state, &pairs).await?;
    assert!(initial.observation.profile.is_some());
    let explicit:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,require_pkce,require_state_parameter,require_iss_parameter,sender_constrained,enforce_refresh_sender_binding,allowed_grant_types,token_endpoint_auth_methods_allowed) SELECT environment_id,configuration_version_id,'explicit','DOWNSTREAM',false,true,false,false,'NONE',true,allowed_grant_types,token_endpoint_auth_methods_allowed FROM aegaeon.oauth_profiles WHERE environment_id=$1 AND is_default RETURNING id")
        .bind(env.environment_id).fetch_one(pool).await?;
    sqlx::query("UPDATE aegaeon.clients SET oauth_profile_id=$1 WHERE environment_id=$2")
        .bind(explicit)
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    let selected = context(&state, &pairs).await?;
    assert_eq!(
        selected.observation.profile.as_ref().map(|p| p.id.as_str()),
        Some(explicit.to_string()).as_deref()
    );
    for sql in ["UPDATE aegaeon.oauth_profiles SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
                "UPDATE aegaeon.oauth_profiles SET expires_at=NULL,status='RETIRED' WHERE id=$1"] {
        sqlx::query(sql).bind(explicit).execute(pool).await?;
        let redirect=location(&refused(&state,&pairs).await?)?;
        assert!(redirect.query_pairs().any(|(k,v)|k=="error_description"&&v=="oauth profile is required"));
    }
    // An explicit unusable profile cannot silently fall back to the live default.
    let bad_jar = vec![
        ("client_id".into(), client.client_id.clone()),
        ("request".into(), "not-a-jwt".into()),
    ];
    let response = response_json(refused(&state, &bad_jar).await?).await?;
    assert!(response["error_description"]
        .as_str()
        .is_some_and(|s| s.contains("request object")));
    sqlx::query("UPDATE aegaeon.clients SET oauth_profile_id=NULL WHERE environment_id=$1")
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    context(&state, &pairs).await?;
    sqlx::query("UPDATE aegaeon.oauth_profiles SET is_default=false WHERE environment_id=$1")
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    assert!(location(&refused(&state, &pairs).await?)?
        .query_pairs()
        .any(|(k, v)| k == "error_description" && v == "oauth profile is required"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn source_mismatch_refuses_before_par_effect_and_before_jar_validation() -> TestResult {
    let pool = required_pool().await?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = source_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn source_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let (state, client) = fixture(pool, env).await?;
    let mut mismatched = state.clone();
    mismatched.environment_id = Uuid::new_v4();
    let mut pairs = plain_pairs(env, &client);
    let response = refused(&mismatched, &pairs).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::LOCATION).is_none());
    pairs.push(("max_age".into(), "not-a-number".into()));
    assert_eq!(
        refused(&mismatched, &pairs).await?.status(),
        StatusCode::BAD_REQUEST
    );
    let bad_jar = vec![
        ("client_id".into(), client.client_id.clone()),
        ("request".into(), "not-a-jwt".into()),
    ];
    assert_eq!(
        refused(&mismatched, &bad_jar).await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let request_uri = crate::par::ParStore::generate_request_uri();
    let request = ParRequest {
        client_id: client.client_id.clone(),
        redirect_uri: client.redirect_uris[0].clone(),
        response_type: "code".into(),
        iss: Some(env.issuer_url.clone()),
        resource: None,
        state: Some("pushed".into()),
        code_challenge: Some("challenge-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
        code_challenge_method: Some("S256".into()),
        scope: Some("openid".into()),
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
                expires_at: SystemTime::now() + Duration::from_secs(45),
                authorize_continuation: None,
            },
        )
        .map_err(io::Error::other)?;
    let pairs = vec![
        ("request_uri".into(), request_uri.clone()),
        ("client_id".into(), client.client_id.clone()),
    ];
    assert_eq!(
        refused(&mismatched, &pairs).await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(crate::par::reserve_authorize_with_par(
        state.protocol.par_store.as_ref(),
        &request_uri,
        &client.client_id
    )
    .is_ok());
    // The source checks require the actual startup instances, not an equal-looking clone.
    let mut wrong_instance = state.clone();
    wrong_instance.cfg = Arc::new((*state.cfg).clone());
    assert_eq!(
        refused(&wrong_instance, &plain_pairs(env, &client))
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let duplicate=sqlx::query("INSERT INTO aegaeon.environments(tenant_id,name,slug,issuer_host) VALUES($1,'duplicate','duplicate-observation',$2)")
        .bind(env.tenant_id).bind(&env.issuer_host).execute(pool).await;
    assert!(
        matches!(duplicate,Err(sqlx::Error::Database(ref error)) if error.code().as_deref()==Some("23505"))
    );
    // Genuine configuration change invalidates the original derivation.
    sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document=jsonb_set(configuration_document,'{policy,requireStateParameter}','false') WHERE environment_id=$1")
        .bind(env.environment_id).execute(pool).await?;
    assert_eq!(
        refused(&state, &plain_pairs(env, &client)).await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn same_document_under_new_configuration_id_refuses_original_runtime() -> TestResult {
    let pool = required_pool().await?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = configuration_id_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn configuration_id_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let (state, client) = fixture(pool, env).await?;
    let pairs = plain_pairs(env, &client);
    context(&state, &pairs).await?;
    let original =
        crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
            pool,
            &env.issuer_host,
        )
        .await?;
    let replacement = Uuid::new_v4();
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE aegaeon.configuration_versions SET status='ARCHIVED' WHERE id=$1")
        .bind(original.active_configuration_version_id())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO aegaeon.configuration_versions(id,environment_id,version_number,configuration_hash,status,configuration_document) SELECT $1,environment_id,version_number+1,configuration_hash,'ACTIVE',configuration_document FROM aegaeon.configuration_versions WHERE id=$2")
        .bind(replacement).bind(original.active_configuration_version_id()).execute(&mut *tx).await?;
    sqlx::query("UPDATE aegaeon.environments SET active_configuration_version_id=$1 WHERE id=$2")
        .bind(replacement)
        .bind(env.environment_id)
        .execute(&mut *tx)
        .await?;
    // Keep the selected client/profile coherent with the replacement so their
    // membership checks cannot conceal a missing startup configuration-ID check.
    for sql in [
        "UPDATE aegaeon.clients SET configuration_version_id=$1 WHERE environment_id=$2",
        "UPDATE aegaeon.oauth_profiles SET configuration_version_id=$1 WHERE environment_id=$2",
    ] {
        sqlx::query(sql)
            .bind(replacement)
            .bind(env.environment_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    let changed =
        crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
            pool,
            &env.issuer_host,
        )
        .await?;
    assert_eq!(changed.active_configuration_version_id(), replacement);
    assert_ne!(
        changed.active_configuration_version_id(),
        original.active_configuration_version_id()
    );
    assert_eq!(
        changed.active_configuration_document_fingerprint(),
        original.active_configuration_document_fingerprint()
    );
    assert_eq!(
        changed.active_runtime_key_set_fingerprint(),
        original.active_runtime_key_set_fingerprint()
    );
    assert_eq!(
        changed.active_dcr_bearer_token_fingerprint(),
        original.active_dcr_bearer_token_fingerprint()
    );
    let response = refused(&state, &pairs).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::LOCATION).is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn remote_jar_uses_actual_selected_key_after_pg_transaction_ends() -> TestResult {
    let pool = required_pool().await?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = remote_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn remote_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let (mut state, mut client) = fixture(pool, env).await?;
    let signing = crate::oidc::OidcSigningKey::from_rsa_pem("observed-key".into(), PEM)?;
    let body = serde_json::to_value(signing.jwks())?;
    let count = Arc::new(AtomicUsize::new(0));
    let count_server = count.clone();
    let pg = pool.clone();
    let environment = env.environment_id;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let uri = format!("http://{}/jwks", listener.local_addr()?);
    let app=axum::Router::new().route("/jwks",axum::routing::get(move || {
        let pg=pg.clone();let body=body.clone();let count=count_server.clone();
        async move {
            // Taking both connections from the two-slot pool would time out if
            // the authorize reader still held its RR transaction during HTTP.
            let acquired=tokio::time::timeout(Duration::from_secs(2),async {
                let mut first=pg.acquire().await?;let second=pg.acquire().await?;
                sqlx::query("UPDATE aegaeon.clients SET redirect_uris=ARRAY['https://later.example/cb'] WHERE environment_id=$1")
                    .bind(environment).execute(&mut *first).await?;
                drop(second);Ok::<(),sqlx::Error>(())
            }).await;
            if !matches!(acquired,Ok(Ok(()))) { return (StatusCode::INTERNAL_SERVER_ERROR,axum::Json(json!({}))); }
            count.fetch_add(1,Ordering::SeqCst);(StatusCode::OK,axum::Json(body))
        }
    }));
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let result=async {
        sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=NULL,jwks_uri=$1 WHERE environment_id=$2")
            .bind(&uri).bind(env.environment_id).execute(pool).await?;
        state.clients=Arc::new(ClientRegistry::new_process_local_with_runtime_policy_for_tests(
            crate::client_registry::ClientAssertionRuntimePolicy::default(),crate::client_registry::JwksRuntimePolicy::new_for_tests_allowing_loopback()));
        client.inline_jwks=None;client.jwks_uri=Some(uri.clone());
        let pairs=signed_pairs(env,&client)?;
        let observed=context(&state,&pairs).await?;
        assert_eq!(count.load(Ordering::SeqCst),1);
        assert_eq!(observed.req.redirect_uri.as_ref(),client.redirect_uris.first());
        assert!(observed.req.request_object_claims.is_some());
        Ok(())
    }.await;
    server.abort();
    let _ = server.await;
    result
}

#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn profile_expiry_uses_one_transaction_time_and_next_request_refuses() -> TestResult {
    let pool = required_pool().await?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = expiry_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn expiry_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let (mut state, client) = fixture(pool, env).await?;
    let expiry:i64=sqlx::query_scalar("UPDATE aegaeon.oauth_profiles SET expires_at=clock_timestamp()+interval '1 second' WHERE environment_id=$1 RETURNING (extract(epoch FROM expires_at)*1000000)::bigint")
        .bind(env.environment_id).fetch_one(pool).await?;
    let b = barriers();
    state.runtime_authority.authorization_read_barriers = Some(b.clone());
    let pairs = plain_pairs(env, &client);
    let uri = format!("/authorize?{}", serde_urlencoded::to_string(&pairs)?).parse()?;
    let advance = async {
        b.observed.wait().await;
        let elapsed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let now: i64 = sqlx::query_scalar(
                    "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint",
                )
                .fetch_one(pool)
                .await?;
                if now >= expiry {
                    break Ok::<(), sqlx::Error>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        b.resume.wait().await;
        elapsed
    };
    let (observed, elapsed) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            build_authorize_request_context(
                &state,
                &uri,
                &env.issuer_url,
                "snapshot-expiry".into()
            ),
            advance
        )
    })
    .await?;
    elapsed??;
    let observed = observed.map_err(|_| io::Error::other("RR read unexpectedly failed"))?;
    assert!(observed.observation.profile.is_some());
    state.runtime_authority.authorization_read_barriers = None;
    assert!(location(&refused(&state, &pairs).await?)?
        .query_pairs()
        .any(|(k, v)| k == "error_description" && v == "oauth profile is required"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn selected_auth_method_preserves_pkce_without_secret_credentials() -> TestResult {
    let pool = required_pool().await?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = confidentiality_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn confidentiality_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let (state, client) = fixture(pool, env).await?;
    assert!(state.cfg.security_policy.require_pkce);
    state.clients.try_register_client_secret_credentials(
        &client.client_id,
        vec![crate::client_registry::ClientSecretCredential::new(
            "synthetic-unused-hash".into(),
            i64::MAX,
        )],
    )?;
    // The real schema requires PKCE for every profile; do not fabricate an
    // inadmissible profile to exercise a currently unreachable policy branch.
    let no_pkce =
        sqlx::query("UPDATE aegaeon.oauth_profiles SET require_pkce=false WHERE environment_id=$1")
            .bind(env.environment_id)
            .execute(pool)
            .await;
    assert!(matches!(no_pkce, Err(sqlx::Error::Database(ref error))
        if error.code().as_deref() == Some("23514")));
    sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=ARRAY['none','client_secret_basic'] WHERE environment_id=$1")
        .bind(env.environment_id).execute(pool).await?;
    sqlx::query("UPDATE aegaeon.clients SET client_type='CONFIDENTIAL',token_endpoint_authentication_method='client_secret_basic' WHERE environment_id=$1")
        .bind(env.environment_id).execute(pool).await?;
    let observed = context(&state, &plain_pairs(env, &client)).await?;
    assert!(observed.pkce_required);
    assert!(observed.profile_pkce_required);
    assert!(observed
        .observation
        .selected_clients
        .try_is_confidential(&client.client_id)?);
    assert!(observed
        .observation
        .selected_clients
        .try_client_secret_credentials(&client.client_id)?
        .is_empty());
    assert_eq!(
        state
            .clients
            .try_client_secret_credentials(&client.client_id)?
            .len(),
        1
    );
    // JAR continues to use public verification material, without client secrets.
    let signed = context(&state, &signed_pairs(env, &client)?).await?;
    assert!(signed.pkce_required);
    assert!(signed.req.request_object_claims.is_some());
    sqlx::query("UPDATE aegaeon.clients SET client_type='PUBLIC',token_endpoint_authentication_method='none' WHERE environment_id=$1")
        .bind(env.environment_id).execute(pool).await?;
    let public = context(&state, &plain_pairs(env, &client)).await?;
    assert!(public.pkce_required);
    assert!(public.profile_pkce_required);
    assert!(!public
        .observation
        .selected_clients
        .try_is_confidential(&client.client_id)?);
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn startup_original_survives_public_copy_changes_and_key_changes_refuse() -> TestResult {
    let pool = required_pool().await?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = key_source_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn key_source_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let (mut state, client) = fixture(pool, env).await?;
    let pairs = plain_pairs(env, &client);
    let mut loaded =
        crate::runtime_configuration::load_database_runtime_configuration(pool, &env.issuer_host)
            .await?;
    loaded.environment_id = Uuid::new_v4();
    loaded.issuer_url = "https://unrelated.example".into();
    loaded.state.policy.oidc_enabled = false;
    loaded.state.policy.require_state_parameter = false;
    loaded.runtime_keys = crate::runtime_keys::RuntimeKeySet::try_new(Vec::new())?;
    let derived =
        derive_test_authorization_runtime(loaded, crate::config::ServerConfig::default()).await?;
    state.cfg = derived.configuration();
    state.oidc.config = derived.oidc();
    state.runtime_authority =
        crate::runtime_authority::RuntimeAuthorityState::from_authorization_runtime(derived);
    assert!(state.cfg.require_state);
    assert!(state.oidc.config.is_some());
    context(&state, &pairs).await?;
    let (id, handle, public): (Uuid, String, Value) = sqlx::query_as(
        "SELECT id,key_handle,public_jwk FROM aegaeon.runtime_keys WHERE environment_id=$1 AND status='ACTIVE'"
    ).bind(env.environment_id).fetch_one(pool).await?;
    // Metadata unused by the typed loader and ineligible NEXT keys do not
    // invalidate an otherwise unchanged consumed runtime-key source.
    sqlx::query("UPDATE aegaeon.runtime_keys SET activated_at=clock_timestamp(),created_at=created_at+interval '1 second' WHERE id=$1")
        .bind(id).execute(pool).await?;
    let next: Uuid = sqlx::query_scalar("INSERT INTO aegaeon.runtime_keys(environment_id,configuration_version_id,usage,kid,algorithm,provider,status,public_jwk,key_handle) SELECT environment_id,configuration_version_id,usage,'unselected-next-key',algorithm,provider,'NEXT',public_jwk,key_handle FROM aegaeon.runtime_keys WHERE id=$1 RETURNING id")
        .bind(id).fetch_one(pool).await?;
    context(&state, &pairs).await?;
    sqlx::query("DELETE FROM aegaeon.runtime_keys WHERE id=$1")
        .bind(next)
        .execute(pool)
        .await?;
    for mutation in [
        "UPDATE aegaeon.runtime_keys SET key_handle=key_handle||'A' WHERE id=$1",
        "UPDATE aegaeon.runtime_keys SET public_jwk=public_jwk||'{\"extra-source-fact\":true}'::jsonb WHERE id=$1",
        "UPDATE aegaeon.runtime_keys SET status='REVOKED' WHERE id=$1",
    ] {
        sqlx::query(mutation).bind(id).execute(pool).await?;
        let response = refused(&state, &pairs).await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get(header::LOCATION).is_none());
        sqlx::query("UPDATE aegaeon.runtime_keys SET key_handle=$1,public_jwk=$2,status='ACTIVE' WHERE id=$3")
            .bind(&handle).bind(&public).bind(id).execute(pool).await?;
        context(&state, &pairs).await?;
    }
    retiring_key_precision(pool, env, &mut state, &pairs).await
}

async fn retiring_key_precision(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    state: &mut AppState,
    pairs: &[(String, String)],
) -> TestResult {
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE aegaeon.runtime_keys SET status='RETIRING',retiring_expires_at=date_trunc('second',clock_timestamp())+interval '1 hour 0.123456 seconds' WHERE environment_id=$1")
        .bind(env.environment_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let loaded =
        crate::runtime_configuration::load_database_runtime_configuration(pool, &env.issuer_host)
            .await?;
    seed_oidc_configuration(pool, env, loaded.state.policy, "new-active-key").await?;
    let loaded =
        crate::runtime_configuration::load_database_runtime_configuration(pool, &env.issuer_host)
            .await?;
    let derived =
        derive_test_authorization_runtime(loaded, crate::config::ServerConfig::default()).await?;
    state.cfg = derived.configuration();
    state.oidc.config = derived.oidc();
    state.runtime_authority =
        crate::runtime_authority::RuntimeAuthorityState::from_authorization_runtime(derived);
    context(state, pairs).await?;
    sqlx::query("UPDATE aegaeon.runtime_keys SET retiring_expires_at=retiring_expires_at+interval '0.000001 seconds' WHERE environment_id=$1 AND status='RETIRING'")
        .bind(env.environment_id).execute(pool).await?;
    assert_eq!(
        refused(state, pairs).await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}
