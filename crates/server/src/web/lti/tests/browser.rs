//! Browser CSP regression against the real handlers, with CDP-owned transport.
//! The browser evaluates origins, forms and redirects; TLS supplier assurance is separate.
use super::*;
use axum::{routing::get, Json};
use serde_json::json;
use std::net::SocketAddr;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and the dedicated Chromium runner"]
async fn pre_migration_lti_browser_consent() -> Result {
    let fixture = Fixture::new(true, false).await?;
    let mut paths = Vec::new();
    for _ in 0..4 {
        paths.push(fixture.create().await?);
    }
    let info = json!({"issuer":fixture.state.issuer,"session":fixture.session,"paths":paths});
    let router = crate::web::build_router(fixture.state.clone()).route(
        "/__fixture_info",
        get(move || async move { Json(info.clone()) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = stopped.await;
        })
        .await
    });
    let result = tokio::process::Command::new("timeout")
        .args(["--kill-after=5s", "45s", "node"])
        .arg(std::env::var("AEGAEON_LTI_BROWSER_SCRIPT")?)
        .arg(format!("http://{address}"))
        .kill_on_drop(true)
        .output()
        .await;
    let _ = stop.send(());
    server.await??;
    let result = result?;
    assert!(
        result.status.success(),
        "browser failed: {} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    println!("{}", String::from_utf8_lossy(&result.stdout));
    for (path, expected) in paths
        .iter()
        .zip(["initiated", "cancelled", "pending", "initiated"])
    {
        let ticket = path.rsplit('/').next().ok_or("missing ticket")?;
        let status: String = sqlx::query_scalar("SELECT status FROM aegaeon.lti_launch_intents WHERE environment_id=$1 AND ticket_hash=$2")
            .bind(fixture.state.environment_id).bind(crate::lti::intents::digest(ticket)).fetch_one(&fixture.state.db_pool).await?;
        assert_eq!(status, expected);
    }
    Ok(())
}
