//! Actual TCP ingress, management authentication and parent/child lifecycle.
use super::*;
use reqwest::{Client, StatusCode};

#[test]
#[ignore = "requires independent TLS stores and v8 control; owns a loopback HTTP ingress"]
fn organization_production_http_management_and_child_fences() -> Result<()> {
    with_environment(tokio::runtime::Builder::new_current_thread(), || async {
        let super::fixture::Context {
            prepared,
            mut control,
            deployment,
            scope,
            initialized,
            ..
        } = super::fixture::prepare(true).await?;
        let (runtime, dispatcher) = super::fixture::build_for_fixture(prepared).await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(super::super::serving::run(
            listener,
            runtime,
            dispatcher,
            async move {
                let _ = shutdown.await;
            },
        ));
        // This is the product's trusted loopback TLS-terminator hop. Store TLS is
        // real; this case does not claim an external ingress TLS implementation.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse()?);
        headers.insert("origin", "https://admin.example.test".parse()?);
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .default_headers(headers)
            .build()?;
        let selected = format!(
            "/api/v1/teams/{}/environments/{}",
            initialized.team_id, initialized.environment_id
        );
        let unknown = format!(
            "/api/v1/teams/{}/environments/{}",
            initialized.team_id,
            Uuid::new_v4()
        );
        let foreign_team = format!(
            "/api/v1/teams/{}/environments/{}",
            Uuid::new_v4(),
            initialized.environment_id
        );
        let result = async {
        check(&client, &base, "/health", "", StatusCode::OK).await?;
        check(&client, &base, "/ready", "", StatusCode::NO_CONTENT).await?;
        check(&client, &base, "/api/v1/system/version", "", StatusCode::OK).await?;
        // Authentication precedes consulting either known or absent child registry entries.
        check(&client, &base, &selected, "", StatusCode::UNAUTHORIZED).await?;
        check(&client, &base, &unknown, "", StatusCode::UNAUTHORIZED).await?;
        let login = client.post(format!("{base}/api/v1/authentication/sessions"))
            .header("cookie", "csrf_token=fixture-csrf")
            .header("x-csrf-token", "fixture-csrf")
            .json(&serde_json::json!({"email":"owner@example.test","password":"Independent-Fixture-Password-7!"}))
            .send().await?;
        anyhow::ensure!(login.status() == StatusCode::NO_CONTENT, "management login: {}", login.status());
        let cookie = login.headers().get_all("set-cookie").iter().filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("aegaeon_admin_session="))
            .and_then(|v| v.split(';').next()).ok_or_else(|| anyhow::anyhow!("missing management session"))?.to_string();
        let _ = login.bytes().await?;
        check(&client, &base, "/api/v1/teams", &cookie, StatusCode::OK).await?;
        check(&client, &base, &selected, &cookie, StatusCode::OK).await?;
        check(&client, &base, &unknown, &cookie, StatusCode::NOT_FOUND).await?;
        check(&client, &base, &foreign_team, &cookie, StatusCode::NOT_FOUND).await?;
        control.environment_maintenance()?.fence(scope, Uuid::new_v4(), 3).await?;
        check(&client, &base, &selected, &cookie, StatusCode::SERVICE_UNAVAILABLE).await?;
        // A child fence cannot be bypassed; unrelated global management can still operate.
        check(&client, &base, "/api/v1/teams", &cookie, StatusCode::OK).await?;
        check(&client, &base, "/ready", "", StatusCode::SERVICE_UNAVAILABLE).await?;
        control.fence(deployment, Uuid::new_v4(), 3).await?;
        check(&client, &base, "/api/v1/teams", &cookie, StatusCode::SERVICE_UNAVAILABLE).await?;
        check(&client, &base, "/health", "", StatusCode::OK).await?;
        Ok::<_, anyhow::Error>(())
    }.await;
        let _ = stop.send(());
        let stopped = tokio::time::timeout(Duration::from_secs(50), server).await;
        let pending = control.pending(deployment).await?.state.pending;
        let child_pending = control
            .environment_maintenance()?
            .pending(scope)
            .await?
            .state
            .pending;
        control.close().await?;
        result?;
        stopped???;
        anyhow::ensure!(
            pending == 0 && child_pending == 0,
            "HTTP work remained pending after shutdown"
        );
        Ok(())
    })
}

async fn check(
    client: &Client,
    base: &str,
    path: &str,
    cookie: &str,
    expected: StatusCode,
) -> Result<()> {
    let response = client
        .get(format!("{base}{path}"))
        .header("cookie", cookie)
        .send()
        .await?;
    let actual = response.status();
    let body = response.bytes().await?;
    // Diagnostics expose only the public route response, never the session cookie.
    anyhow::ensure!(
        actual == expected,
        "{path}: expected {expected}, got {actual}: {}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}
