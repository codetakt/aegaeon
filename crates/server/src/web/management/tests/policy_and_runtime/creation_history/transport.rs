use sqlx::ConnectOptions;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

async fn upstream(options: &sqlx::postgres::PgConnectOptions) -> std::io::Result<Box<dyn Stream>> {
    let socket = options.get_socket().cloned().or_else(|| {
        options
            .get_host()
            .starts_with('/')
            .then(|| options.get_host().into())
    });
    if let Some(directory) = socket {
        Ok(Box::new(
            tokio::net::UnixStream::connect(
                directory.join(format!(".s.PGSQL.{}", options.get_port())),
            )
            .await?,
        ))
    } else {
        let stream =
            tokio::net::TcpStream::connect((options.get_host(), options.get_port())).await?;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
}

async fn relay(
    listener: tokio::net::TcpListener,
    options: sqlx::postgres::PgConnectOptions,
    armed: Arc<AtomicBool>,
    committed: tokio::sync::oneshot::Sender<()>,
) -> std::io::Result<()> {
    let (client, _) = listener.accept().await?;
    client.set_nodelay(true)?;
    let server = upstream(&options).await?;
    let (mut upload_read, mut download_write) = client.into_split();
    let (mut download_read, mut upload_write) = tokio::io::split(server);
    let upload = async {
        tokio::io::copy(&mut upload_read, &mut upload_write).await?;
        Ok::<(), std::io::Error>(())
    };
    let download = async {
        loop {
            let mut header = [0u8; 5];
            download_read.read_exact(&mut header).await?;
            let length =
                u32::from_be_bytes(header[1..].try_into().map_err(std::io::Error::other)?) as usize;
            if !(4..=16 * 1024 * 1024).contains(&length) {
                return Err(std::io::Error::other("fixture PostgreSQL frame bound"));
            }
            let mut body = vec![0; length - 4];
            download_read.read_exact(&mut body).await?;
            if header[0] == b'C' && body == b"COMMIT\0" && armed.load(Ordering::Acquire) {
                // PostgreSQL has completed the real commit. Drop its actual
                // CommandComplete and ReadyForQuery, with no fabricated reply.
                let _ = committed.send(());
                download_write.shutdown().await?;
                return Ok::<(), std::io::Error>(());
            }
            download_write.write_all(&header).await?;
            download_write.write_all(&body).await?;
        }
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL; suppress the actual primary COMMIT acknowledgement after creating the user and receipt"]
async fn pg_organizations_creation_management_commit_acknowledgement_loss() -> TestResult {
    creation_commit_acknowledgement_loss(false).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; suppress actual primary COMMIT acknowledgement for the complete CSV batch"]
async fn pg_organizations_creation_csv_commit_acknowledgement_loss() -> TestResult {
    creation_commit_acknowledgement_loss(true).await
}
async fn creation_commit_acknowledgement_loss(csv: bool) -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let options = (*f.user.runtime.connect_options()).clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    // Preserve fixture authentication but clear any Unix socket alias. Never log this URL.
    let mut url = options.to_url_lossy();
    url.set_host(Some("127.0.0.1")).map_err(|_| "proxy host")?;
    url.set_port(Some(address.port()))
        .map_err(|_| "proxy port")?;
    let proxy_options: sqlx::postgres::PgConnectOptions = url.as_str().parse()?;
    let armed = Arc::new(AtomicBool::new(false));
    let (committed, observed) = tokio::sync::oneshot::channel();
    let proxy = tokio::spawn(tokio::time::timeout(
        std::time::Duration::from_secs(12),
        relay(listener, options, armed.clone(), committed),
    ));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect_with(proxy_options.ssl_mode(sqlx::postgres::PgSslMode::Disable))
        .await?;
    let result=history_test(async {
        let mgmt=test_management_state();
        let sid=mgmt.sessions.create(f.user.env.administrator_id,crate::util::now_unix_epoch_secs()?).ok_or("session")?;
        let app=super::super::super::build_router(test_app_state(pool.clone(),mgmt)?);
        let key=Uuid::new_v4().to_string();
        let mut request=membership_http_request(Method::POST,&f.user.env,if csv {"users/importCsv"} else {"users"},&sid,
            if csv {csv_body(true)} else {serde_json::json!({"subject":"lost-ack","email":"owner@example.com"})})?;
        request.headers_mut().insert("idempotency-key",key.parse()?);
        let mut barrier=f.user.admin.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.organization_creation_receipts IN SHARE MODE").execute(&mut *barrier).await?;
        let work=f.witness.begin().await?;
        let closure=work.admission().closure_probe_for_test();
        let label=work.admission().store_label()?.ok_or("work label")?.to_owned();
        let owner=work.admission().clone();
        let execution=tokio::spawn(async move {owner.store_scope(app.oneshot(request)).await});
        let waiting=creation_primary_wait(&f.user.admin,&label).await;
        armed.store(true,Ordering::Release);
        let release=barrier.rollback().await;
        let response=execution.await;
        waiting.map_err(|e|format!("primary receipt wait (csv={csv}): {e}"))?;release?;
        tokio::time::timeout(std::time::Duration::from_secs(3),observed).await
            .map_err(|e|format!("commit observer wait (csv={csv}): {e}"))??;
        assert!(response?.is_err());
        assert!(closure.is_closed() && work.complete().await.is_err());
        let (id,state,attempt)=f.witness.retained_creation(if csv {"csv-a"} else {"lost-ack"}).await?;
        assert_eq!((state,attempt),("reserved".into(),1));
        let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.end_users WHERE id=$1),(SELECT count(*) FROM aegaeon.organization_creation_receipts WHERE owner_id=$1)")
            .bind(id).fetch_one(&f.user.runtime).await?;
        assert_eq!(counts,(1,1),"actual commit must survive lost acknowledgement");
        let before=f.user.snapshot().await?;
        let retry=if csv {retained_csv_request(&f,&[&key],csv_body(true)).await?} else {creation_request(&f,&[&key],"lost-ack").await?};
        assert!(!retry.status().is_success());
        if csv {
            let (second,state,attempt)=f.witness.retained_creation("csv-b").await?;
            assert_eq!((state,attempt),("reserved".into(),1));
            let n:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_creation_receipts WHERE owner_id=$1")
                .bind(second).fetch_one(&f.user.runtime).await?;
            assert_eq!(n,1);assert_eq!(retained_csv_counts(&f).await?,(2,2,2));
        }
        assert_eq!(before,f.user.snapshot().await?);
        assert_eq!(f.witness.pending().await?,1);
        Ok(())
    }).await;
    let proxy = proxy.await;
    let closed = tokio::time::timeout(std::time::Duration::from_secs(3), pool.close()).await;
    let result = result.and((|| -> TestResult {
        proxy?.map_err(|e| format!("relay lifetime (csv={csv}): {e}"))??;
        closed.map_err(|e| format!("proxy pool cleanup (csv={csv}): {e}"))?;
        Ok(())
    })());
    f.finish(result).await
}
