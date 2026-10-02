use super::*;

pub(super) async fn run(state: &mut AppState, sid: &str) -> TestResult {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    state.protocol.stepup_store = Arc::new(
        crate::stepup::StepUpStore::try_from_shared_store_env_with_ttl_secs(300, &namespace)?,
    );
    for mode in [
        "plain",
        "jar-login-consent-zero-age",
        "par-login-consent-zero-age",
    ] {
        let uri = if mode == "plain" {
            format!("{}&max_age=0", authorize_uri(state, Some("login consent"))?)
        } else {
            request_uri(state, sid, mode).await?
        };
        let mut browser = Browser::default();
        browser
            .cookies
            .insert("aegaeon_auth_session".into(), sid.into());
        let page = post_input(&mut browser, state, &uri).await?;
        let login = page.location.ok_or("login")?;
        let page = browser.request(state, &login, None).await?;
        let return_to = field(&page.body, "return_to")?;
        let token = return_to
            .strip_prefix("/authorize?aeg_login_continue=")
            .ok_or("opaque")?;
        let hash = URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(token.as_bytes()));
        let snapshot:Value=sqlx::query_scalar("SELECT request_snapshot FROM aegaeon.authorization_logins WHERE environment_id=$1 AND token_sha256=$2")
            .bind(state.environment_id).bind(hash).fetch_one(&state.db_pool).await?;
        let req: crate::authcode::types::AuthorizationRequest =
            serde_json::from_value(snapshot["request"].clone())?;
        let request_id = crate::web::authorize_endpoint::stepup_request_id(&req, None, Some(0));
        let now = crate::util::now_unix_epoch_secs()?;
        // An outstanding challenge is the existing adapter's input. The actual
        // local password route must bind its transfer to the retained request.
        assert!(state
            .protocol
            .stepup_store
            .try_issue_challenge(CLIENT, sid, &request_id, now)?
            .is_some());
        let csrf = field(&page.body, "csrf_token")?;
        let logged =
            super::super::negative::login(&mut browser, state, &return_to, &csrf, PASSWORD).await?;
        assert_eq!(logged.status, StatusCode::SEE_OTHER, "{}", logged.body);
        let new_sid = browser
            .cookies
            .get("aegaeon_auth_session")
            .ok_or("session")?;
        assert_ne!(new_sid, sid);
        let now = crate::util::now_unix_epoch_secs()?;
        assert!(state.protocol.stepup_store.try_consume_completed(
            CLIENT,
            new_sid,
            &request_id,
            now
        )?);
        assert!(!state.protocol.stepup_store.try_consume_completed(
            CLIENT,
            new_sid,
            &request_id,
            now
        )?);
        let consent = browser.request(state, &return_to, None).await?;
        assert_eq!(consent.status, StatusCode::OK, "{}", consent.body);
        let token = transaction(&consent.body)?.to_string();
        let response = browser
            .request(
                state,
                "/auth/consent",
                Some(vec![("transaction", &token), ("decision", "approve")]),
            )
            .await?;
        check_code(state, &browser, &response, false).await?;
    }
    Ok(())
}
