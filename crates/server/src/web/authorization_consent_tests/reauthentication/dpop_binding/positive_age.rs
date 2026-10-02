use super::*;

pub(super) async fn run(state: &AppState, _sid: &str, post: bool) -> TestResult {
    let key = Key::new(state)?;
    positive_sources(state, &key, post).await?;
    {
        let age = 1;
        let now = crate::util::now_unix_epoch_secs()?;
        let old_sid = state
            .browser_auth
            .auth_sessions
            .create(
                "consent-user",
                AuthSessionTimes::local(now - 120),
                None,
                None,
                None,
            )
            .ok_or("old session")?;
        let mut pairs = fields(state, Some("consent"))?;
        pairs.push(("dpop_jkt".into(), key.jkt.clone()));
        pairs.push(("max_age".into(), age.to_string()));
        let mut browser = Browser::default();
        browser
            .cookies
            .insert("aegaeon_auth_session".into(), old_sid.clone());
        let page = authorize(&mut browser, state, &pairs, post).await?;
        let login = page.location.ok_or("login")?;
        let page = browser.request(state, &login, None).await?;
        let target = field(&page.body, "return_to")?;
        let csrf = field(&page.body, "csrf_token")?;
        let opaque = target
            .strip_prefix("/authorize?aeg_login_continue=")
            .ok_or("opaque")?;
        let hash = URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(opaque.as_bytes()));
        let snapshot:Value=sqlx::query_scalar("SELECT request_snapshot FROM aegaeon.authorization_logins WHERE environment_id=$1 AND token_sha256=$2").bind(state.environment_id).bind(hash).fetch_one(&state.db_pool).await?;
        let req: crate::authcode::types::AuthorizationRequest =
            serde_json::from_value(snapshot["request"].clone())?;
        assert_eq!(
            req.dpop_jkt.as_ref().map(DpopKeyThumbprint::as_str),
            Some(key.jkt.as_str())
        );
        let id = crate::web::authorize_endpoint::stepup_request_id(&req, None, Some(age));
        assert!(state
            .protocol
            .stepup_store
            .try_issue_challenge(CLIENT, &old_sid, &id, now)?
            .is_some());
        let logged = negative::login(&mut browser, state, &target, &csrf, PASSWORD).await?;
        assert_eq!(logged.status, StatusCode::SEE_OTHER);
        let sid = browser
            .cookies
            .get("aegaeon_auth_session")
            .ok_or("new sid")?;
        assert_ne!(sid, &old_sid);
        let sid = sid.clone();
        let completed = completed_receipt(state, &sid, &id)?;
        let before = state.tokens.issuer.code_store.snapshot().codes.len();
        tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
        let stale = browser.request(state, &target, None).await?;
        assert_eq!(stale.status, StatusCode::BAD_REQUEST, "{}", stale.body);
        let error: Value = serde_json::from_str(&stale.body)?;
        assert_eq!(error["error"], "invalid_request");
        assert_eq!(error["error_description"], "authentication continuation is invalid, expired or already used; restart authorization");
        assert_eq!(
            state.tokens.issuer.code_store.snapshot().codes.len(),
            before
        );
        assert_eq!(completed_receipt(state, &sid, &id)?, completed);
        let now = crate::util::now_unix_epoch_secs()?;
        assert!(state
            .protocol
            .stepup_store
            .try_consume_completed(CLIENT, &sid, &id, now)?);
        assert!(!state
            .protocol
            .stepup_store
            .try_consume_completed(CLIENT, &sid, &id, now)?);
        assert!(browser
            .request(state, &target, None)
            .await?
            .status
            .is_client_error());
    }
    Ok(())
}

// Observe the actual transferred Redis record without consuming it before the
// HTTP continuation under test. Challenges are seeded test inputs; production
// login completion and session transfer are the operations being observed.
pub(super) fn completed_receipt(
    state: &AppState,
    sid: &str,
    request: &str,
) -> TestResult<Vec<String>> {
    let ns = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let prefix = ns.redis_prefix("stepup", "v3");
    let lookup = format!("{CLIENT}::{sid}::{request}");
    let mut hash = aegaeon_crypto::hash::Sha256Hasher::new();
    hash.update(b"aegaeon:stepup:request:v3");
    hash.update(&(lookup.len() as u64).to_be_bytes());
    hash.update(lookup.as_bytes());
    let storage = format!(
        "{prefix}:request:{}",
        URL_SAFE_NO_PAD.encode(hash.finalize())
    );
    let mut conn =
        redis::Client::open(std::env::var("AEGAEON_STEPUP_REDIS_URL")?)?.get_connection()?;
    let challenge: String = redis::cmd("GET").arg(&storage).query(&mut conn)?;
    let values: Vec<String> = redis::cmd("HMGET")
        .arg(format!("{prefix}:challenge:{challenge}"))
        .arg(&[
            "client_id",
            "session_id",
            "request_id",
            "completed",
            "request_redis_key",
            "expires_at_epoch_secs",
        ])
        .query(&mut conn)?;
    assert_eq!(&values[..5], &[CLIENT, sid, request, "1", &storage]);
    assert!(values[5].parse::<u64>()? > crate::util::now_unix_epoch_secs()?);
    Ok(values)
}
pub(super) fn signed_age(state: &AppState, key: Option<&Key>) -> TestResult<String> {
    let jwt = signed(state, key.map(|key| json!(key.jkt)), None)?;
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).ok_or("claims")?)?)?;
    claims["max_age"] = json!(60);
    claims["prompt"] = json!("consent");
    sign_claims(&claims)
}
pub(super) fn old_session(state: &AppState) -> TestResult<String> {
    state
        .browser_auth
        .auth_sessions
        .create(
            "consent-user",
            AuthSessionTimes::local(crate::util::now_unix_epoch_secs()? - 120),
            None,
            None,
            None,
        )
        .ok_or_else(|| "old session".into())
}
async fn positive_sources(state: &AppState, key: &Key, post: bool) -> TestResult {
    for source in [
        "plain",
        "jar",
        "par-parameter",
        "par-header",
        "par-both",
        "par-jar-header",
        "par-jar-claim",
        "par-jar-both",
    ] {
        let sid = old_session(state)?;
        let jar = source.contains("jar");
        let header = source.contains("header") || source.ends_with("both");
        let parameter = !header || source.ends_with("both");
        let mut pairs = if jar {
            vec![
                ("client_id".into(), CLIENT.into()),
                (
                    "request".into(),
                    signed_age(state, parameter.then_some(key))?,
                ),
            ]
        } else {
            let mut pairs = fields(state, Some("consent"))?;
            pairs.push(("max_age".into(), "60".into()));
            if parameter {
                pairs.push(("dpop_jkt".into(), key.jkt.clone()));
            }
            pairs
        };
        if source.starts_with("par-") {
            let proof = header
                .then(|| key.proof(state, "/par", json!({})))
                .transpose()?;
            let (status, body) = par::submit(state, &sid, &pairs, proof.as_deref()).await?;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            pairs = vec![
                ("client_id".into(), CLIENT.into()),
                (
                    "request_uri".into(),
                    body["request_uri"].as_str().ok_or("uri")?.into(),
                ),
            ];
        }
        let mut browser = Browser::default();
        browser.cookies.insert("aegaeon_auth_session".into(), sid);
        let page = authorize(&mut browser, state, &pairs, post).await?;
        assert!(page
            .location
            .as_deref()
            .is_some_and(|location| location.starts_with("/auth/login")));
        let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
        redeem_bound(state, &code, key).await?;
    }
    Ok(())
}
