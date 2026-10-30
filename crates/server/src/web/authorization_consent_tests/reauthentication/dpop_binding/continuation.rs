use super::*;

pub(super) async fn run(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    let other = Key::new(state)?;
    let mut pairs = fields(state, Some("login consent"))?;
    pairs.push(("dpop_jkt".into(), key.jkt.clone()));
    pairs.push(("max_age".into(), "0".into()));
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let page = authorize(&mut browser, state, &pairs, true).await?;
    let login = page.location.as_deref().ok_or("login")?;
    let (id,original):(Uuid,Value)=sqlx::query_as("SELECT id,request_snapshot FROM aegaeon.authorization_logins WHERE environment_id=$1 ORDER BY created_at DESC LIMIT 1")
        .bind(state.environment_id).fetch_one(&state.db_pool).await?;
    let before = state.tokens.issuer.code_store.snapshot().codes.len();
    for path in ["input", "request", "missing", "malformed", "legacy"] {
        let mut changed = original.clone();
        match path {
            "input" => {
                for pair in changed["input"]["parameters"]["pairs"]
                    .as_array_mut()
                    .ok_or("pairs")?
                {
                    if pair[0] == "dpop_jkt" {
                        pair[1] = json!(other.jkt);
                    }
                }
            }
            "request" => changed["request"]["dpop_jkt"] = json!(other.jkt),
            "missing" => {
                changed["request"]
                    .as_object_mut()
                    .ok_or("request")?
                    .remove("dpop_jkt");
            }
            "malformed" => changed["request"]["dpop_jkt"] = json!("bad"),
            _ => changed["version"] = json!(2),
        }
        sqlx::query("UPDATE aegaeon.authorization_logins SET request_snapshot=$1 WHERE id=$2 AND environment_id=$3")
            .bind(changed).bind(id).bind(state.environment_id).execute(&state.db_pool).await?;
        let mut rejected = browser.request(state, login, None).await?;
        if matches!(path, "input" | "request") {
            // A well-formed snapshot can bind the login form. Completion rebuilds
            // its effective input and checks equality before recording a receipt.
            assert_eq!(rejected.status, StatusCode::OK, "{path}: {}", rejected.body);
            let target = field(&rejected.body, "return_to")?;
            let csrf = field(&rejected.body, "csrf_token")?;
            rejected = negative::login(&mut browser, state, &target, &csrf, PASSWORD).await?;
        }
        assert_eq!(
            rejected.status,
            StatusCode::BAD_REQUEST,
            "{path}: {}",
            rejected.body
        );
        assert_eq!(
            state.tokens.issuer.code_store.snapshot().codes.len(),
            before
        );
        let (completed, consumed): (bool, bool) = sqlx::query_as(
            "SELECT completed_at IS NOT NULL,consumed_at IS NOT NULL FROM aegaeon.authorization_logins WHERE id=$1",
        ).bind(id).fetch_one(&state.db_pool).await?;
        assert!(!completed && !consumed, "{path}");
        sqlx::query("UPDATE aegaeon.authorization_logins SET request_snapshot=$1 WHERE id=$2 AND environment_id=$3")
            .bind(&original).bind(id).bind(state.environment_id).execute(&state.db_pool).await?;
    }
    sqlx::query("UPDATE aegaeon.authorization_logins SET request_snapshot=$1 WHERE id=$2 AND environment_id=$3")
        .bind(&original).bind(id).bind(state.environment_id).execute(&state.db_pool).await?;
    let mut req: crate::authcode::types::AuthorizationRequest =
        serde_json::from_value(original["request"].clone())?;
    let a = crate::web::authorize_endpoint::stepup_request_id(&req, None, Some(0));
    req.dpop_jkt = Some(DpopKeyThumbprint::parse(&other.jkt)?);
    let b = crate::web::authorize_endpoint::stepup_request_id(&req, None, Some(0));
    assert_ne!(a, b);
    let now = crate::util::now_unix_epoch_secs()?;
    assert!(state
        .protocol
        .stepup_store
        .try_issue_challenge(CLIENT, sid, &a, now)?
        .is_some());
    let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
    let new_sid = browser
        .cookies
        .get("aegaeon_auth_session")
        .ok_or("new session")?;
    assert_ne!(new_sid, sid);
    let now = crate::util::now_unix_epoch_secs()?;
    assert!(!state
        .protocol
        .stepup_store
        .try_consume_completed(CLIENT, new_sid, &b, now)?);
    assert!(state
        .protocol
        .stepup_store
        .try_consume_completed(CLIENT, new_sid, &a, now)?);
    redeem_bound(state, &code, &key).await
}
