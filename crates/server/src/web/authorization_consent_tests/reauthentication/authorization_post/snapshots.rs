use super::*;

struct Pending {
    browser: Browser,
    login: String,
    return_to: String,
    id: Uuid,
    snapshot: Value,
}

async fn begin(state: &AppState, sid: &str) -> TestResult<Pending> {
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let uri = format!("{}&max_age=0", authorize_uri(state, Some("login consent"))?);
    let page = post_input(&mut browser, state, &uri).await?;
    assert_eq!(page.status, StatusCode::FOUND, "{}", page.body);
    let login = page.location.ok_or("login")?;
    let page = browser.request(state, &login, None).await?;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let return_to = field(&page.body, "return_to")?;
    let token = return_to
        .strip_prefix("/authorize?aeg_login_continue=")
        .ok_or("opaque return")?;
    let digest = URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(token.as_bytes()));
    let (id,snapshot,locator):(Uuid,Value,String)=sqlx::query_as("SELECT id,request_snapshot,authorize_uri FROM aegaeon.authorization_logins WHERE environment_id=$1 AND token_sha256=$2")
        .bind(state.environment_id).bind(digest).fetch_one(&state.db_pool).await?;
    assert_eq!(locator, "/authorize");
    assert!(!snapshot.to_string().contains(token));
    assert_eq!(snapshot["version"], 3);
    assert_eq!(snapshot["input"]["provenance"], "form");
    let submitted: Vec<(String, String)> =
        serde_urlencoded::from_str(uri.split_once('?').ok_or("query")?.1)?;
    assert_eq!(
        snapshot["input"]["parameters"]["pairs"],
        serde_json::to_value(submitted)?
    );
    Ok(Pending {
        browser,
        login,
        return_to,
        id,
        snapshot,
    })
}

async fn replace(state: &AppState, pending: &Pending, value: &Value) -> TestResult {
    sqlx::query("UPDATE aegaeon.authorization_logins SET request_snapshot=$1 WHERE id=$2 AND environment_id=$3")
        .bind(value).bind(pending.id).bind(state.environment_id).execute(&state.db_pool).await?;
    Ok(())
}

async fn unconsumed(state: &AppState, id: Uuid, completed: bool) -> TestResult {
    let (is_completed,is_consumed):(bool,bool)=sqlx::query_as("SELECT completed_at IS NOT NULL,consumed_at IS NOT NULL FROM aegaeon.authorization_logins WHERE id=$1")
        .bind(id).fetch_one(&state.db_pool).await?;
    assert_eq!(is_completed, completed);
    assert!(!is_consumed);
    Ok(())
}

async fn malformed(state: &AppState, pending: &mut Pending) -> TestResult {
    let old = serde_json::json!({"request":pending.snapshot["request"],"prompt":pending.snapshot["prompt"],"response_mode":pending.snapshot["response_mode"]});
    let mut invalid = vec![old.clone()];
    for version in [
        serde_json::json!(1),
        serde_json::json!(2),
        serde_json::json!(4),
        serde_json::json!("2"),
    ] {
        let mut value = pending.snapshot.clone();
        value["version"] = version;
        invalid.push(value);
    }
    for field in [
        "version",
        "input",
        "par_continuation",
        "authentication_session",
    ] {
        let mut value = pending.snapshot.clone();
        value.as_object_mut().ok_or("object")?.remove(field);
        invalid.push(value);
    }
    let mut unknown = pending.snapshot.clone();
    unknown["unexpected"] = serde_json::json!(true);
    invalid.push(unknown);
    let mut nested = pending.snapshot.clone();
    nested["input"]["unexpected"] = serde_json::json!(true);
    invalid.push(nested);
    let mut duplicate = pending.snapshot.clone();
    duplicate["input"]["parameters"]["pairs"]
        .as_array_mut()
        .ok_or("pairs")?
        .push(serde_json::json!(["client_id", CLIENT]));
    invalid.push(duplicate);
    let mut receipt = pending.snapshot.clone();
    receipt["reauthenticated"] = serde_json::json!(true);
    invalid.push(receipt);
    for value in invalid {
        replace(state, pending, &value).await?;
        let page = pending.browser.request(state, &pending.login, None).await?;
        assert_eq!(page.status, StatusCode::BAD_REQUEST, "{}", page.body);
        unconsumed(state, pending.id, false).await?;
    }
    replace(state, pending, &pending.snapshot).await?;
    // Explicit old-reader fixtures: the original unversioned snapshot cannot
    // equal v3; neither its stored locator nor the opaque browser URI contains
    // the client/response fields needed by the old query-only context builder.
    assert_ne!(old, pending.snapshot);
    for uri in ["/authorize", pending.return_to.as_str()] {
        let input = crate::web::authorize_input::AdmittedAuthorizationInput::query(&uri.parse()?)
            .map_err(|_| "query")?;
        let raw = input.raw(None).map_err(|_| "lowering")?;
        assert!(raw.client_id.is_none() && raw.response_type.is_none());
    }
    Ok(())
}

async fn changed_before_complete(state: &AppState, pending: &mut Pending) -> TestResult {
    for path in ["request", "input"] {
        let page = pending.browser.request(state, &pending.login, None).await?;
        let csrf = field(&page.body, "csrf_token")?;
        let mut changed = pending.snapshot.clone();
        if path == "request" {
            changed["request"]["state"] = serde_json::json!("changed-resolved-state");
        } else {
            for pair in changed["input"]["parameters"]["pairs"]
                .as_array_mut()
                .ok_or("pairs")?
            {
                if pair[0] == "state" {
                    pair[1] = serde_json::json!("changed-admitted-state");
                }
            }
        }
        replace(state, pending, &changed).await?;
        let page = super::super::negative::login(
            &mut pending.browser,
            state,
            &pending.return_to,
            &csrf,
            PASSWORD,
        )
        .await?;
        assert_eq!(page.status, StatusCode::BAD_REQUEST, "{}", page.body);
        unconsumed(state, pending.id, false).await?;
        replace(state, pending, &pending.snapshot).await?;
    }
    sqlx::query("UPDATE aegaeon.authorization_logins SET client_id='other-client' WHERE id=$1")
        .bind(pending.id)
        .execute(&state.db_pool)
        .await?;
    assert_eq!(
        pending
            .browser
            .request(state, &pending.login, None)
            .await?
            .status,
        StatusCode::BAD_REQUEST
    );
    sqlx::query("UPDATE aegaeon.authorization_logins SET client_id=$1 WHERE id=$2")
        .bind(CLIENT)
        .bind(pending.id)
        .execute(&state.db_pool)
        .await?;
    Ok(())
}

async fn complete(state: &AppState, pending: &mut Pending) -> TestResult {
    let page = pending.browser.request(state, &pending.login, None).await?;
    let csrf = field(&page.body, "csrf_token")?;
    let page = super::super::negative::login(
        &mut pending.browser,
        state,
        &pending.return_to,
        &csrf,
        PASSWORD,
    )
    .await?;
    assert_eq!(page.status, StatusCode::SEE_OTHER, "{}", page.body);
    Ok(())
}

fn session_record(
    state: &AppState,
    pending: &Pending,
) -> TestResult<(redis::Connection, String, String)> {
    let sid = pending
        .browser
        .cookies
        .get("aegaeon_auth_session")
        .ok_or("session")?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let key = format!(
        "{}:session:{sid}",
        namespace.redis_prefix("auth-session", "v2")
    );
    let mut connection =
        redis::Client::open(std::env::var("AEGAEON_AUTH_SESSION_REDIS_URL")?)?.get_connection()?;
    let bytes: String = redis::cmd("GET").arg(&key).query(&mut connection)?;
    Ok((connection, key, bytes))
}

async fn session_and_consent(state: &AppState, pending: &mut Pending) -> TestResult {
    complete(state, pending).await?;
    changed_during_resume(state, pending).await?;
    let (mut redis, key, original) = session_record(state, pending)?;
    let mut changed: Value = serde_json::from_str(&original)?;
    let auth_time = changed["auth_time_epoch_secs"]
        .as_u64()
        .ok_or("auth time")?;
    changed["auth_time_epoch_secs"] = serde_json::json!(auth_time - 1);
    redis::cmd("SET")
        .arg(&key)
        .arg(changed.to_string())
        .arg("KEEPTTL")
        .query::<()>(&mut redis)?;
    let page = pending
        .browser
        .request(state, &pending.return_to, None)
        .await?;
    assert_eq!(page.status, StatusCode::BAD_REQUEST, "{}", page.body);
    unconsumed(state, pending.id, true).await?;
    redis::cmd("SET")
        .arg(&key)
        .arg(&original)
        .arg("KEEPTTL")
        .query::<()>(&mut redis)?;
    let page = pending
        .browser
        .request(state, &pending.return_to, None)
        .await?;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let token = transaction(&page.body)?.to_string();
    redis::cmd("SET")
        .arg(&key)
        .arg(changed.to_string())
        .arg("KEEPTTL")
        .query::<()>(&mut redis)?;
    let rejected = pending
        .browser
        .request(
            state,
            "/auth/consent",
            Some(vec![("transaction", &token), ("decision", "approve")]),
        )
        .await?;
    assert_eq!(
        rejected.status,
        StatusCode::BAD_REQUEST,
        "{}",
        rejected.body
    );
    redis::cmd("SET")
        .arg(&key)
        .arg(&original)
        .arg("KEEPTTL")
        .query::<()>(&mut redis)?;
    let mut other = pending.browser.clone();
    let (a, b) = tokio::join!(
        pending.browser.request(
            state,
            "/auth/consent",
            Some(vec![("transaction", &token), ("decision", "approve")])
        ),
        other.request(
            state,
            "/auth/consent",
            Some(vec![("transaction", &token), ("decision", "deny")])
        )
    );
    let (a, b) = (a?, b?);
    assert_eq!(
        usize::from(a.status == StatusCode::FOUND) + usize::from(b.status == StatusCode::FOUND),
        1
    );
    let success = if a.status == StatusCode::FOUND { a } else { b };
    let url = url::Url::parse(success.location.as_deref().ok_or("response")?)?;
    if url.query_pairs().any(|(k, _)| k == "code") {
        check_code(state, &pending.browser, &success, false).await?;
    } else {
        assert!(url
            .query_pairs()
            .any(|(k, v)| k == "error" && v == "access_denied"));
    }
    assert_eq!(
        pending
            .browser
            .request(state, &pending.return_to, None)
            .await?
            .status,
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

pub(super) async fn run(state: &AppState, sid: &str) -> TestResult {
    let mut pending = begin(state, sid).await?;
    malformed(state, &mut pending).await?;
    changed_before_complete(state, &mut pending).await?;
    for suffix in [
        "&state=changed",
        "&unknown=x",
        "&aeg_login_continue=",
        "&aeg_login_continue=duplicate",
    ] {
        let page = pending
            .browser
            .request(state, &format!("{}{suffix}", pending.return_to), None)
            .await?;
        assert_eq!(page.status, StatusCode::BAD_REQUEST);
    }
    session_and_consent(state, &mut pending).await?;
    let mut expired = begin(state, sid).await?;
    sqlx::query(
        "UPDATE aegaeon.authorization_logins SET expires_at=now()-interval '1 second' WHERE id=$1",
    )
    .bind(expired.id)
    .execute(&state.db_pool)
    .await?;
    assert_eq!(
        expired
            .browser
            .request(state, &expired.login, None)
            .await?
            .status,
        StatusCode::BAD_REQUEST
    );
    let mut missing = begin(state, sid).await?;
    sqlx::query("DELETE FROM aegaeon.authorization_logins WHERE id=$1")
        .bind(missing.id)
        .execute(&state.db_pool)
        .await?;
    assert_eq!(
        missing
            .browser
            .request(state, &missing.login, None)
            .await?
            .status,
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

async fn changed_during_resume(state: &AppState, pending: &Pending) -> TestResult {
    let barriers = crate::runtime_authority::AuthorizationReadBarriers {
        observed: Arc::new(tokio::sync::Barrier::new(2)),
        resume: Arc::new(tokio::sync::Barrier::new(2)),
    };
    let mut selected = state.clone();
    selected.runtime_authority.authorization_context_barriers = Some(barriers.clone());
    let mut browser = pending.browser.clone();
    let mut changed = pending.snapshot.clone();
    changed["request"]["state"] = serde_json::json!("changed-during-resume");
    let mutate = async {
        barriers.observed.wait().await;
        let result = replace(state, pending, &changed).await;
        barriers.resume.wait().await;
        result
    };
    let (page, changed) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(browser.request(&selected, &pending.return_to, None), mutate)
    })
    .await?;
    changed?;
    assert_eq!(page?.status, StatusCode::BAD_REQUEST);
    unconsumed(state, pending.id, true).await?;
    replace(state, pending, &pending.snapshot).await
}

pub(super) async fn policy(state: &mut AppState, sid: &str) -> TestResult {
    let mut pending = begin(state, sid).await?;
    complete(state, &mut pending).await?;
    let mut client = state.clients.try_get(CLIENT)?.ok_or("client")?;
    client.allowed_scopes.retain(|s| s != "email");
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=$1 WHERE environment_id=$2 AND client_identifier=$3")
        .bind(&client.allowed_scopes).bind(state.environment_id).bind(CLIENT).execute(&state.db_pool).await?;
    assert!(state.clients.try_update(client)?);
    let page = pending
        .browser
        .request(state, &pending.return_to, None)
        .await?;
    if let Some(location) = page.location {
        let url = url::Url::parse(&location)?;
        assert!(url
            .query_pairs()
            .any(|(k, v)| k == "error" && v == "invalid_scope"));
        assert!(!url.query_pairs().any(|(k, _)| k == "code"));
    } else {
        assert!(
            page.status.is_client_error(),
            "{} {}",
            page.status,
            page.body
        );
        assert_eq!(
            serde_json::from_str::<Value>(&page.body)?["error"],
            "invalid_scope"
        );
    }
    unconsumed(state, pending.id, true).await
}
