use super::*;

async fn profile(state: &AppState, grants: &[&str]) -> TestResult {
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1 WHERE environment_id=$2")
        .bind(grants)
        .bind(state.environment_id)
        .execute(&state.db_pool)
        .await?;
    Ok(())
}
fn failing_par(state: &AppState, url: &str) -> TestResult<AppState> {
    let mut failing = state.clone();
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let store = Arc::new(crate::par::ParStore::redis_for_tests(url, 90, &namespace)?);
    let metrics = aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?;
    failing.protocol.par_endpoint = Arc::new(crate::par::ParEndpoint::new(
        Arc::new(crate::metrics_integration::MetricsIntegration::new(
            Arc::new(metrics),
        )),
        store.clone(),
    ));
    failing.protocol.par_store = store;
    Ok(failing)
}
pub(super) async fn run(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    let pairs = vec![
        ("client_id".into(), CLIENT.into()),
        ("request".into(), signed(state, Some(json!(key.jkt)), None)?),
    ];
    // The Request Object has passed signature/key checks, but profile rejection
    // occurs before the separate jti admission boundary.
    profile(state, &["refresh_token"]).await?;
    let before = par::saved_count(state)?;
    let (status, body) = par::submit(state, sid, &pairs, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "unauthorized_client");
    assert_eq!(par::saved_count(state)?, before);
    profile(state, &["authorization_code", "refresh_token"]).await?;
    assert_eq!(
        par::submit(state, sid, &pairs, None).await?.0,
        StatusCode::CREATED
    );
    let (status, body) = par::submit(state, sid, &pairs, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body["error_description"]
        .as_str()
        .ok_or("description")?
        .contains("replay"));
    persistence_failure(state, sid, &key).await
}
async fn persistence_failure(state: &AppState, sid: &str, key: &Key) -> TestResult {
    let name = format!("par-fault-{}", Uuid::new_v4());
    let password = Uuid::new_v4().to_string();
    let redis_url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let mut conn = redis::Client::open(redis_url.clone())?.get_connection()?;
    // An isolated synthetic ACL user denies only SET, including the real PAR
    // persistence operation. The real shared JAR and DPoP stores remain intact.
    redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&name)
        .arg("reset")
        .arg("on")
        .arg(format!(">{password}"))
        .arg("~*")
        .arg("+@all")
        .arg("-set")
        .query::<()>(&mut conn)?;
    let result = async {
        let mut url = url::Url::parse(&redis_url)?;
        url.set_username(&name).map_err(|()| "username")?;
        url.set_password(Some(&password)).map_err(|()| "password")?;
        let failing = failing_par(state, url.as_str())?;
        let pairs = vec![
            ("client_id".into(), CLIENT.into()),
            ("request".into(), signed(state, Some(json!(key.jkt)), None)?),
        ];
        let count = par::saved_count(state)?;
        let proof = key.proof(state, "/par", json!({}))?;
        let (status, body) = par::submit(&failing, sid, &pairs, Some(&proof)).await?;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["error"], "server_error");
        assert_eq!(par::saved_count(state)?, count);
        // The failed later SET does not roll either replay identity back.
        let (status, body) = par::submit(state, sid, &pairs, Some(&proof)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_dpop_proof");
        let proof = key.proof(state, "/par", json!({}))?;
        let (status, body) = par::submit(state, sid, &pairs, Some(&proof)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
        assert!(body["error_description"]
            .as_str()
            .ok_or("description")?
            .contains("replay"));
        assert_eq!(par::saved_count(state)?, count);
        let fresh = vec![
            ("client_id".into(), CLIENT.into()),
            ("request".into(), signed(state, Some(json!(key.jkt)), None)?),
        ];
        assert_eq!(
            par::submit(state, sid, &fresh, None).await?.0,
            StatusCode::CREATED
        );
        Ok(())
    }
    .await;
    let deleted: i64 = redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&name)
        .query(&mut conn)?;
    assert_eq!(deleted, 1);
    result
}
