use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
    ConnectOptions, Executor,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
enum Fault {
    BeforeSql,
    DuringWrite,
    Permanent,
    LostCommitAck,
}

async fn snapshot(f: &BindingFixture) -> Result<serde_json::Value, sqlx::Error> {
    sqlx::query_scalar("SELECT jsonb_build_array((SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]') FROM aegaeon.account_links t WHERE environment_id=$1),(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]') FROM aegaeon.connections t WHERE environment_id=$1),(SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND request_id='outage-request'))")
        .bind(f.env.environment_id).fetch_one(&f.pool).await
}

fn request(
    f: &BindingFixture,
    op: usize,
    link: Uuid,
    sid: &str,
) -> Result<Request<Body>, Box<dyn StdError>> {
    let (method, path, body) = match op {
        0 => (
            Method::POST,
            "accountLinks".to_owned(),
            serde_json::json!({"connectionId":f.connection,"upstreamSubject":"outage-new","endUserId":f.users[0]}),
        ),
        1 => (
            Method::DELETE,
            format!("accountLinks/{link}"),
            serde_json::json!({}),
        ),
        _ => (
            Method::DELETE,
            format!("connections/{}", f.connection),
            serde_json::json!({}),
        ),
    };
    let mut request = membership_http_request(method, &f.env, &path, sid, body)?;
    if op != 0 {
        *request.body_mut() = Body::empty();
    }
    request
        .headers_mut()
        .insert("x-request-id", "outage-request".parse()?);
    request.headers_mut().insert(
        "aegaeon-base-configuration-version-id",
        f.env.configuration_version_id.to_string().parse()?,
    );
    Ok(request)
}

async fn wait_and_terminate(admin: &sqlx::PgPool, label: &str) -> TestResult {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT DISTINCT a.pid FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.application_name=$1 AND NOT l.granted AND l.locktype='advisory' AND a.datname=current_database()")
                .bind(label).fetch_optional(admin).await?;
            if let Some(pid) = pid {
                assert!(sqlx::query_scalar::<_,bool>("SELECT pg_terminate_backend($1)").bind(pid).fetch_one(admin).await?);
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await??;
    Ok(())
}

async fn run_fault(op: usize, fault: Fault) -> TestResult {
    let f = BindingFixture::new().await?;
    let admin = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(
            std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?
                .parse::<PgConnectOptions>()?
                .database(f.pool.connect_options().get_database().ok_or("database")?),
        )
        .await?;
    let label = format!("management-outage-{}", Uuid::new_v4());
    let direct = f
        .pool
        .connect_options()
        .as_ref()
        .clone()
        .application_name(&label);
    let mut proxy = None;
    let mut observed = None;
    let armed = Arc::new(AtomicBool::new(false));
    let options = if matches!(fault, Fault::LostCommitAck) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut url = direct.to_url_lossy();
        url.set_host(Some("127.0.0.1")).map_err(|_| "proxy host")?;
        url.set_port(Some(address.port()))
            .map_err(|_| "proxy port")?;
        let (committed, receiver) = tokio::sync::oneshot::channel();
        observed = Some(receiver);
        proxy = Some(tokio::spawn(tokio::time::timeout(
            Duration::from_secs(12),
            super::creation_transport::relay(listener, direct.clone(), armed.clone(), committed),
        )));
        url.as_str()
            .parse::<PgConnectOptions>()?
            .ssl_mode(PgSslMode::Disable)
    } else {
        direct
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect_with(options)
        .await?;
    let table = if op == 2 {
        "connections"
    } else {
        "account_links"
    };
    let event = ["INSERT", "DELETE", "UPDATE"][op];
    let row = if op == 1 { "OLD" } else { "NEW" };
    let key = Uuid::new_v4().as_u128() as i64;
    let result: TestResult = async {
        let link = if op == 1 { f.legacy("outage-existing").await? } else { Uuid::nil() };
        let before = snapshot(&f).await?;
        let management = test_management_state();
        let sid = management.sessions.create(f.env.administrator_id, crate::util::now_unix_epoch_secs()?).ok_or("session")?;
        let app = super::super::super::build_router(test_app_state(pool.clone(), management)?);
        let mut barrier = None;
        if matches!(fault, Fault::DuringWrite | Fault::Permanent) {
            let body = if matches!(fault, Fault::DuringWrite) { format!("PERFORM pg_advisory_xact_lock({key});") }
                else { "RAISE SQLSTATE '42501' USING MESSAGE='private-credential-detail';".into() };
            // Interrupt only after the row has changed, so the final snapshot exercises rollback.
            let timing = if matches!(fault, Fault::DuringWrite) { "AFTER" } else { "BEFORE" };
            admin.execute(format!("CREATE FUNCTION aegaeon.management_outage_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {body} RETURN {row}; END $$").as_str()).await?;
            admin.execute(format!("CREATE TRIGGER management_outage_fault {timing} {event} ON aegaeon.{table} FOR EACH ROW WHEN ({row}.environment_id='{}'::uuid) EXECUTE FUNCTION aegaeon.management_outage_fault()", f.env.environment_id).as_str()).await?;
            if matches!(fault, Fault::DuringWrite) {
                let mut held = admin.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(key).execute(&mut *held).await?;
                barrier = Some(held);
            }
        }
        if matches!(fault, Fault::BeforeSql) { pool.close().await; }
        armed.store(true, Ordering::Release);
        let execution = tokio::spawn(app.oneshot(request(&f, op, link, &sid)?));
        let termination = if barrier.is_some() { wait_and_terminate(&admin, &label).await } else { Ok(()) };
        if let Some(held) = barrier { held.rollback().await?; }
        termination?;
        let response = tokio::time::timeout(Duration::from_secs(8), execution).await???;
        let status = if matches!(fault, Fault::Permanent) { StatusCode::INTERNAL_SERVER_ERROR } else { StatusCode::SERVICE_UNAVAILABLE };
        assert_eq!(response.status(), status, "operation={op}, fault={fault:?}");
        assert_eq!(response.headers()["x-request-id"], "outage-request");
        assert!(response.headers()["cache-control"].to_str()?.contains("no-store"));
        assert_eq!(response.headers().get("retry-after").map(|v| v.to_str().unwrap()),
            (status == StatusCode::SERVICE_UNAVAILABLE).then_some("1"));
        let body = response_json(response).await?;
        assert_eq!(body["requestId"], "outage-request");
        assert_eq!(body["errorCode"], if status == StatusCode::SERVICE_UNAVAILABLE {"temporarily_unavailable"} else {"internal_error"});
        assert!(!body.to_string().contains("private-credential-detail"));
        if let Some(observed) = observed.take() {
            tokio::time::timeout(Duration::from_secs(3), observed).await??;
            let after = snapshot(&f).await?;
            assert_eq!(after[2], 1, "state and audit survive actual committed reply loss");
            match op {
                0 => {
                    assert_eq!(after[0].as_array().ok_or("links")?.len(), 1);
                    // A later owner change makes conflict insufficient to identify the lost result.
                    sqlx::query("UPDATE aegaeon.account_links SET end_user_id=$1 WHERE environment_id=$2").bind(f.users[1]).bind(f.env.environment_id).execute(&admin).await?;
                }
                1 => {
                    assert!(after[0].as_array().ok_or("links")?.is_empty());
                    let replacement = f.legacy("outage-existing").await?;
                    assert_ne!(replacement, link);
                }
                _ => assert_eq!(after[1][0]["status"], "DELETED"),
            }
            let retry = f.app.clone().oneshot(request(&f, op, link, &f.sid)?).await?;
            assert_eq!(retry.status(), if op == 0 { StatusCode::CONFLICT } else { StatusCode::NOT_FOUND });
            assert_eq!(snapshot(&f).await?[2], 1, "diagnostic replay must not add a success audit");
        } else { assert_eq!(snapshot(&f).await?, before, "failed write must leave state and audit unchanged"); }
        Ok(())
    }.await;
    // Remove only this fixture's fault resources, even when an assertion fails via Result.
    let trigger_cleanup = if matches!(fault, Fault::DuringWrite | Fault::Permanent) {
        admin.execute(format!("DROP TRIGGER IF EXISTS management_outage_fault ON aegaeon.{table}; DROP FUNCTION IF EXISTS aegaeon.management_outage_fault()").as_str()).await.map(|_| ())
    } else {
        Ok(())
    };
    let proxy_result: TestResult = if let Some(proxy) = proxy {
        async {
            proxy.await???;
            Ok(())
        }
        .await
    } else {
        Ok(())
    };
    pool.close().await;
    admin.close().await;
    let cleanup = f.cleanup().await;
    result?;
    trigger_cleanup?;
    proxy_result?;
    cleanup?;
    Ok(())
}

#[test]
#[ignore = "requires isolated PostgreSQL; real HTTP writes before SQL, mid-write termination, permanent SQL and lost COMMIT reply"]
fn pg_management_outage_write_boundaries_and_audit_atomicity() -> TestResult {
    let capture = crate::web::test_support::log_capture::Capture::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    tracing::subscriber::with_default(capture.subscriber(), || {
        runtime.block_on(async {
            for op in 0..3 {
                for fault in [
                    Fault::BeforeSql,
                    Fault::DuringWrite,
                    Fault::Permanent,
                    Fault::LostCommitAck,
                ] {
                    run_fault(op, fault).await?;
                }
            }
            assert!(!capture.text().contains("private-credential-detail"));
            assert!(capture.text().contains("42501") && capture.text().contains("source_file="));
            Ok(())
        })
    })
}
