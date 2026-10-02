use super::*;
use crate::middleware::replay_store::{ReplayEntry, ReplayStore, ReplayStoreError};
use crate::middleware::{dpop::DpopNonceStore, DpopMiddleware};
use std::time::Duration;
struct Unavailable;
impl ReplayStore for Unavailable {
    fn check_and_store(&self, _: ReplayEntry<'_>) -> Result<(), ReplayStoreError> {
        Err(ReplayStoreError::BackendUnavailable(
            "isolated unavailable backend".into(),
        ))
    }
}
pub(super) async fn run(original: &AppState, sid: &str) -> TestResult {
    let mut state = original.clone();
    let nonce = DpopNonceStore::redis(
        &std::env::var("AEGAEON_TEST_REDIS_URL")?,
        format!("binding-nonce-{}", state.environment_id),
        Duration::from_secs(300),
    )?;
    state.dpop = Arc::new(
        state
            .dpop
            .as_ref()
            .clone()
            .with_nonce_store(Arc::new(nonce)),
    );
    let key = Key::new(&state)?;
    let pairs = fields(&state, None)?;
    for claims in [json!({}), json!({"nonce":"wrong"})] {
        let proof = key.proof(&state, "/par", claims)?;
        let response = raw(
            &state,
            sid,
            Method::POST,
            "/par",
            serde_urlencoded::to_string(&pairs)?,
            form_headers(Some(&proof))?,
        )
        .await?;
        assert!(response.headers().get("DPoP-Nonce").is_some());
        let (status, value) = json_reply(response).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value["error"], "use_dpop_nonce");
    }
    let nonce = state
        .dpop
        .current_nonce()
        .map_err(|e| format!("nonce: {e:?}"))?
        .ok_or("nonce")?;
    let proof = key.proof(&state, "/par", json!({"nonce":nonce}))?;
    let mut unavailable = state.clone();
    unavailable.dpop = Arc::new(
        DpopMiddleware::new(
            "binding-fault",
            state.issuer.as_str(),
            Arc::new(Unavailable),
            Duration::from_secs(360),
        )
        .with_native_verifier_for_tests(),
    );
    let response = raw(
        &unavailable,
        sid,
        Method::POST,
        "/par",
        serde_urlencoded::to_string(&pairs)?,
        form_headers(Some(&proof))?,
    )
    .await?;
    let (status, body) = json_reply(response).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "temporarily_unavailable");
    let response = raw(
        &state,
        sid,
        Method::POST,
        "/par",
        serde_urlencoded::to_string(&pairs)?,
        form_headers(Some(&proof))?,
    )
    .await?;
    let (status, body) = json_reply(response).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let pairs = vec![
        ("client_id".into(), CLIENT.into()),
        (
            "request_uri".into(),
            body["request_uri"].as_str().ok_or("uri")?.into(),
        ),
    ];
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let page = authorize(&mut browser, &state, &pairs, false).await?;
    let code = finish(&mut browser, &state, page, Some(&key.jkt)).await?;
    let proof = key.proof(&state, "/token", json!({"nonce":nonce}))?;
    assert_eq!(token(&state, &code, Some(&proof)).await?.0, StatusCode::OK);
    Ok(())
}
