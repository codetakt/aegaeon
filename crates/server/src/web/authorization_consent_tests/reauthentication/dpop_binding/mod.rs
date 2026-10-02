//! Native DPoP + actual browser/PAR/token routes with PostgreSQL and Redis.
use super::*;
use crate::authcode::types::{CnfClaim, DpopKeyThumbprint, SenderBinding};
use crate::web::test_support::native_dpop;
use axum::http::{HeaderMap, Method};
use serde_json::json;
mod admission;
mod continuation;
mod descendants;
mod edges;
mod encrypted;
mod flows;
mod lifecycle;
mod literal_discriminators;
mod nonce;
mod par;
mod positive_age;
mod protection_restart;
mod replay;
mod snapshot;
mod storage_guards;
mod stored;
mod token_guards;

struct Key {
    material: aegaeon_crypto::signing::Ed25519KeyData,
    jkt: String,
}
impl Key {
    fn new(state: &AppState) -> TestResult<Self> {
        let material = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let proof = native_dpop::proof(state, &material, json!({}))?;
        let jkt = crate::util::compute_dpop_jkt_from_proof(&proof).ok_or("jkt")?;
        Ok(Self { material, jkt })
    }
    fn proof(&self, state: &AppState, path: &str, extra: Value) -> TestResult<String> {
        let mut claims = json!({"htu":format!("{}{path}", state.issuer)});
        for (name, value) in extra.as_object().ok_or("claims")? {
            claims[name] = value.clone();
        }
        native_dpop::proof(state, &self.material, claims)
    }
}

async fn raw(
    state: &AppState,
    sid: &str,
    method: Method,
    uri: &str,
    body: String,
    headers: HeaderMap,
) -> TestResult<axum::response::Response> {
    let app = crate::web::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, format!("aegaeon_auth_session={sid}"));
    request.headers_mut().ok_or("headers")?.extend(headers);
    Ok(app.oneshot(request.body(Body::from(body))?).await?)
}
fn form_headers(proof: Option<&str>) -> TestResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse()?,
    );
    if let Some(proof) = proof {
        headers.insert("DPoP", proof.parse()?);
    }
    Ok(headers)
}
fn request_headers(state: &AppState, proof: Option<&str>) -> TestResult<HeaderMap> {
    let mut headers = form_headers(proof)?;
    let client = state.clients.try_get(CLIENT)?.ok_or("client")?;
    if client.token_endpoint_auth_method == "client_secret_basic" {
        let secret = CLIENT_SECRET.to_string();
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT}:{secret}"));
        headers.insert(header::AUTHORIZATION, format!("Basic {encoded}").parse()?);
    }
    Ok(headers)
}
fn stored_par(state: &AppState, uri: &str) -> TestResult<(Value, Option<String>)> {
    let (mut connection, request, reservation) = par_keys(state, uri)?;
    let bytes: String = redis::cmd("GET").arg(request).query(&mut connection)?;
    let continuation: Option<String> = redis::cmd("GET").arg(reservation).query(&mut connection)?;
    Ok((serde_json::from_str(&bytes)?, continuation))
}
fn par_keys(state: &AppState, uri: &str) -> TestResult<(redis::Connection, String, String)> {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let prefix = namespace.redis_atomic_group_prefix(
        crate::config::RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
        "par",
        "v3",
    );
    let mut hash = aegaeon_crypto::hash::Sha256Hasher::new();
    hash.update(b"aegaeon:par:v3");
    hash.update(&(uri.len() as u64).to_be_bytes());
    hash.update(uri.as_bytes());
    let digest = URL_SAFE_NO_PAD.encode(hash.finalize());
    let connection =
        redis::Client::open(std::env::var("AEGAEON_PAR_REDIS_URL")?)?.get_connection()?;
    Ok((
        connection,
        format!("{prefix}:req:{digest}"),
        format!("{prefix}:reservation:{digest}"),
    ))
}
async fn json_reply(response: axum::response::Response) -> TestResult<(StatusCode, Value)> {
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    Ok((
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?,
    ))
}
fn fields(state: &AppState, prompt: Option<&str>) -> TestResult<Vec<(String, String)>> {
    Ok(serde_urlencoded::from_str(
        authorize_uri(state, prompt)?
            .split_once('?')
            .ok_or("query")?
            .1,
    )?)
}
fn signed(state: &AppState, dpop: Option<Value>, prompt: Option<&str>) -> TestResult<String> {
    let jwt = request_objects::signed_request(state, "query-mode-no-prompt")?;
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).ok_or("claims")?)?)?;
    if let Some(value) = dpop {
        claims["dpop_jkt"] = value;
    }
    if let Some(prompt) = prompt {
        claims["prompt"] = json!(prompt);
        claims["max_age"] = json!(0);
    }
    sign_claims(&claims)
}
fn sign_claims(claims: &Value) -> TestResult<String> {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.typ = Some("oauth-authz-req+jwt".into());
    Ok(jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../../../../../tests/fixtures/rsa2048-private.pk8.pem"
        ))?,
    )?)
}
async fn authorize(
    browser: &mut Browser,
    state: &AppState,
    pairs: &[(String, String)],
    post: bool,
) -> TestResult<Page> {
    if post {
        browser
            .request(
                state,
                "/authorize",
                Some(
                    pairs
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect(),
                ),
            )
            .await
    } else {
        browser
            .request(
                state,
                &format!("/authorize?{}", serde_urlencoded::to_string(pairs)?),
                None,
            )
            .await
    }
}
async fn complete_login(
    browser: &mut Browser,
    state: &AppState,
    mut page: Page,
    expected: Option<&str>,
) -> TestResult<Page> {
    let login = page.location.ok_or("login")?;
    page = browser.request(state, &login, None).await?;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let target = field(&page.body, "return_to")?;
    let opaque = target
        .strip_prefix("/authorize?aeg_login_continue=")
        .ok_or("opaque login")?;
    let hash = URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(opaque.as_bytes()));
    let snapshot:Value=sqlx::query_scalar("SELECT request_snapshot FROM aegaeon.authorization_logins WHERE environment_id=$1 AND token_sha256=$2")
            .bind(state.environment_id).bind(hash).fetch_one(&state.db_pool).await?;
    assert_eq!(snapshot["version"], 3);
    assert_eq!(
        snapshot["request"]["dpop_jkt"],
        expected.map_or(Value::Null, |s| json!(s))
    );
    let req: crate::authcode::types::AuthorizationRequest =
        serde_json::from_value(snapshot["request"].clone())?;
    let request_id = crate::web::authorize_endpoint::stepup_request_id(
        &req,
        None,
        crate::web::authorize_endpoint::authorize_requested_max_age(&req),
    );
    let old_sid = browser
        .cookies
        .get("aegaeon_auth_session")
        .ok_or("old sid")?
        .clone();
    let issued = state
        .protocol
        .stepup_store
        .try_issue_challenge(
            CLIENT,
            &old_sid,
            &request_id,
            crate::util::now_unix_epoch_secs()?,
        )?
        .is_some();
    let challenge = issued.then_some((old_sid, request_id));
    let csrf = field(&page.body, "csrf_token")?;
    page = negative::login(browser, state, &target, &csrf, PASSWORD).await?;
    assert_eq!(page.status, StatusCode::SEE_OTHER, "{}", page.body);
    if let Some((old_sid, request_id)) = challenge {
        let new_sid = browser
            .cookies
            .get("aegaeon_auth_session")
            .ok_or("session")?;
        assert_ne!(&old_sid, new_sid);
        positive_age::completed_receipt(state, new_sid, &request_id)?;
    }
    page = browser.request(state, &target, None).await?;
    Ok(page)
}
async fn finish(
    browser: &mut Browser,
    state: &AppState,
    mut page: Page,
    expected: Option<&str>,
) -> TestResult<String> {
    if page
        .location
        .as_deref()
        .is_some_and(|uri| uri.starts_with("/auth/login"))
    {
        page = complete_login(browser, state, page, expected).await?;
    }
    if page.status == StatusCode::OK && page.body.contains("/auth/consent") {
        let transaction = transaction(&page.body)?.to_string();
        page = browser
            .request(
                state,
                "/auth/consent",
                Some(vec![("transaction", &transaction), ("decision", "approve")]),
            )
            .await?;
    }
    let code = if page.status == StatusCode::OK {
        field(&page.body, "code")?
    } else {
        assert_eq!(page.status, StatusCode::FOUND, "{}", page.body);
        let url = url::Url::parse(page.location.as_deref().ok_or("code redirect")?)?;
        url.query_pairs()
            .find(|(name, _)| name == "code")
            .ok_or("code")?
            .1
            .into_owned()
    };
    let record = state
        .tokens
        .issuer
        .code_store
        .try_get_code(&code)?
        .ok_or("stored code")?;
    assert_eq!(
        record.dpop_jkt.as_ref().map(DpopKeyThumbprint::as_str),
        expected
    );
    Ok(code)
}
async fn token(
    state: &AppState,
    code: &str,
    proof: Option<&str>,
) -> TestResult<(StatusCode, Value)> {
    json_reply(
        raw(
            state,
            "",
            Method::POST,
            "/token",
            serde_urlencoded::to_string([
                ("grant_type", "authorization_code"),
                ("client_id", CLIENT),
                ("code", code),
                ("redirect_uri", "https://client.example.com/callback"),
                ("code_verifier", VERIFIER),
            ])?,
            request_headers(state, proof)?,
        )
        .await?,
    )
    .await
}
async fn redeem_bound(state: &AppState, code: &str, key: &Key) -> TestResult {
    let (mut conn, storage, bytes_before) = storage_guards::stored_code(state, code)?;
    let before = serde_json::to_value(state.tokens.issuer.code_store.try_get_code(code)?)?;
    let wrong = Key::new(state)?;
    for (proof, error) in [
        (None, "invalid_dpop_proof"),
        (Some("malformed".to_string()), "invalid_dpop_proof"),
        (
            Some(wrong.proof(state, "/token", json!({}))?),
            "invalid_grant",
        ),
    ] {
        let counts = state.tokens.store.try_snapshot()?;
        let (status, body) = token(state, code, proof.as_deref()).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], error);
        assert_eq!(
            serde_json::to_value(state.tokens.issuer.code_store.try_get_code(code)?)?,
            before
        );
        let bytes_after: String = redis::cmd("GET").arg(&storage).query(&mut conn)?;
        assert_eq!(bytes_before, bytes_after);
        let after = state.tokens.store.try_snapshot()?;
        assert_eq!(counts.access_tokens.len(), after.access_tokens.len());
        assert_eq!(counts.refresh_tokens.len(), after.refresh_tokens.len());
    }
    let proof = key.proof(state, "/token", json!({}))?;
    let (status, body) = token(state, code, Some(&proof)).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "DPoP");
    let saved = state
        .tokens
        .store
        .try_verify_access_token(body["access_token"].as_str().ok_or("access")?)?
        .ok_or("saved access")?;
    assert_eq!(saved.cnf, Some(CnfClaim::Jkt(key.jkt.clone())));
    if let Some(refresh) = body["refresh_token"].as_str() {
        assert_eq!(
            state
                .tokens
                .store
                .try_get_refresh_token(refresh)?
                .ok_or("refresh")?
                .sender_binding,
            Some(SenderBinding::DPoP {
                jkt: key.jkt.clone()
            })
        );
    }
    assert!(state.tokens.issuer.code_store.try_get_code(code)?.is_none());
    Ok(())
}

async fn run(case: &str) -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let method = if case.starts_with("snapshot") || case.ends_with("confidential") {
            "client_secret_basic"
        } else {
            "none"
        };
        let (mut state, _) = fixture_with_auth_method(&pool, &env, method).await?;
        user(&pool, &env).await?;
        update_test_policy(&mut state, |p| p.strict_authorize_redirect = true).await?;
        request_objects::shared_protocol_stores(&mut state)?;
        native_dpop::install(&mut state)?;
        let namespace =
            crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
        state.protocol.stepup_store = Arc::new(
            crate::stepup::StepUpStore::try_from_shared_store_env_with_ttl_secs(300, &namespace)?,
        );
        let sid = state
            .browser_auth
            .auth_sessions
            .create(
                "consent-user",
                AuthSessionTimes::local(crate::util::now_unix_epoch_secs()?),
                None,
                None,
                None,
            )
            .ok_or("session")?;
        match case {
            "literal-discriminators" => literal_discriminators::run(&state, &sid).await,
            "snapshot-later-profile" => snapshot::later_profile(&state, &sid).await,
            "encrypted-positive-age" => encrypted::positive_age(&mut state, &sid).await,
            "positive-age" => positive_age::run(&state, &sid, true).await,
            "positive-age-get" => positive_age::run(&state, &sid, false).await,
            "storage-guards" => storage_guards::run(&state, &sid).await,
            "protection-restart" => protection_restart::run(&state, &sid).await,
            "legacy" => stored::legacy(&state, &sid).await,
            "stored-modes" => stored::modes(&state, &sid, false).await,
            "stored-login-modes" => stored::modes(&state, &sid, true).await,
            "stored-records" => stored::records(&state, &sid).await,
            "proof-edges" | "proof-edges-confidential" => edges::proofs(&state, &sid).await,
            "duplicate-claims" => edges::duplicate_claims(&state, &sid).await,
            "replay" => replay::run(&state, &sid).await,
            "descendants" | "descendants-confidential" => descendants::run(&mut state, &sid).await,
            "mtls" => token_guards::mtls(&state, &sid).await,
            "grant-guards" => token_guards::grant_guards(&state, &sid).await,
            "snapshot-before" => snapshot::run(&state, &sid, false, false).await,
            "snapshot-after" => snapshot::run(&state, &sid, true, false).await,
            "snapshot-before-jar" => snapshot::run(&state, &sid, false, true).await,
            "snapshot-after-jar" => snapshot::run(&state, &sid, true, true).await,
            "confidential" => flows::run(&state, &sid, true, false).await,
            "flows-get" => flows::run(&state, &sid, false, false).await,
            "flows-post" => flows::run(&state, &sid, true, false).await,
            "flows-get-login" => flows::run(&state, &sid, false, true).await,
            "flows-post-login" => flows::run(&state, &sid, true, true).await,
            "unbound" => flows::unbound(&state, &sid).await,
            "encrypted" => encrypted::run(&mut state, &sid).await,
            "continuation" => continuation::run(&state, &sid).await,
            "nonce" => nonce::run(&state, &sid).await,
            "admission" => admission::run(&state, &sid).await,
            "par" => par::run(&state, &sid).await,
            _ => Err("unknown case".into()),
        }
    }
    .await;
    let cleanup=async {
        sqlx::query("DELETE FROM aegaeon.end_user_password_credentials WHERE end_user_id IN (SELECT id FROM aegaeon.end_users WHERE environment_id=$1)").bind(env.environment_id).execute(&pool).await?;
        sqlx::query("DELETE FROM aegaeon.end_users WHERE environment_id=$1").bind(env.environment_id).execute(&pool).await?;
        cleanup_test_environment(&pool,&env).await
    }.await;
    finish_test(result, cleanup)
}
macro_rules! binding_test {
    ($name:ident,$case:literal) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL and Redis; real native DPoP"]
        async fn $name() -> TestResult {
            run($case).await
        }
    };
}
binding_test!(
    shared_redis_authorization_code_dpop_binding_get_sources,
    "flows-get"
);
binding_test!(
    shared_redis_authorization_code_dpop_binding_post_sources,
    "flows-post"
);
binding_test!(
    shared_redis_authorization_code_dpop_binding_get_login_consent_sources,
    "flows-get-login"
);
binding_test!(
    shared_redis_authorization_code_dpop_binding_post_login_consent_sources,
    "flows-post-login"
);
binding_test!(
    shared_redis_authorization_code_dpop_binding_optional_token_proof,
    "unbound"
);
binding_test!(
    shared_redis_authorization_code_dpop_binding_strict_admission,
    "admission"
);
binding_test!(
    shared_redis_authorization_code_dpop_binding_par_proofs,
    "par"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_encrypted_active_retiring,
    "encrypted"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_snapshot_stepup_tamper,
    "continuation"
);
binding_test!(
    shared_redis_authorization_code_dpop_binding_par_nonce_backend,
    "nonce"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_par_snapshot_before,
    "snapshot-before"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_par_snapshot_after,
    "snapshot-after"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_par_snapshot_before_jar,
    "snapshot-before-jar"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_par_snapshot_after_jar,
    "snapshot-after-jar"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_confidential,
    "confidential"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_stored_modes,
    "stored-modes"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_stored_login_modes,
    "stored-login-modes"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_stored_records,
    "stored-records"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_proof_edges,
    "proof-edges"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_proof_edges_confidential,
    "proof-edges-confidential"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_duplicate_claims,
    "duplicate-claims"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_replay,
    "replay"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_descendants,
    "descendants"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_descendants_confidential,
    "descendants-confidential"
);

binding_test!(shared_redis_authorization_code_dpop_binding_mtls, "mtls");

binding_test!(
    shared_redis_authorization_code_dpop_binding_grant_guards,
    "grant-guards"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_legacy_namespaces,
    "legacy"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_later_profile,
    "snapshot-later-profile"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_positive_age,
    "positive-age"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_storage_guards,
    "storage-guards"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_retained_protection,
    "protection-restart"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_encrypted_positive_age,
    "encrypted-positive-age"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_positive_age_get,
    "positive-age-get"
);

binding_test!(
    shared_redis_authorization_code_dpop_binding_literal_discriminators,
    "literal-discriminators"
);
