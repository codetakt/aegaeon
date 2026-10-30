use super::*;
use tokio::io::AsyncWriteExt;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; cuts actual server replies while server work continues"]
async fn pg_organizations_transport_close_does_not_confirm_server_completion() -> TestResult {
    let direct: sqlx::postgres::PgConnectOptions =
        std::env::var("AEGAEON_DATABASE_URL")?.parse()?;
    let directory = direct
        .get_socket()
        .cloned()
        .or_else(|| {
            direct
                .get_host()
                .starts_with('/')
                .then(|| direct.get_host().into())
        })
        .ok_or("isolated Unix-socket fixture required")?;
    let socket = directory.join(format!(".s.PGSQL.{}", direct.get_port()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (cut, cut_rx) = oneshot::channel();
    let (stop, stop_rx) = oneshot::channel();
    let proxy = tokio::spawn(async move {
        let (client, _) = listener.accept().await?;
        let upstream = tokio::net::UnixStream::connect(socket).await?;
        let (mut client_read, mut client_write) = client.into_split();
        let (mut upstream_read, mut upstream_write) = upstream.into_split();
        let upload = async {
            tokio::io::copy(&mut client_read, &mut upstream_write).await?;
            // Keep the server transport open after the client closes;
            // Terminate is queued behind the in-flight query, not an ACK.
            let _ = stop_rx.await;
            Ok::<(), std::io::Error>(())
        };
        let download = async {
            tokio::select! {
                result = tokio::io::copy(&mut upstream_read, &mut client_write) => { result?; }
                _ = cut_rx => { client_write.shutdown().await?; }
            }
            Ok::<(), std::io::Error>(())
        };
        tokio::try_join!(upload, download)?;
        Ok::<(), std::io::Error>(())
    });
    // Build an explicit TCP destination; do not inherit the fixture socket alias.
    let options = sqlx::postgres::PgConnectOptions::new_without_pgpass()
        .host("127.0.0.1")
        .port(address.port())
        .username(direct.get_username())
        .database(direct.get_database().ok_or("database")?)
        .ssl_mode(sqlx::postgres::PgSslMode::Disable);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect_with(options)
        .await?;
    let mut observer = PgConnection::connect_with(&direct).await?;
    let limit = Arc::new(Semaphore::new(1));
    let lease = Admission::from_limit(&limit)?;
    let mut connection = lease.connection(&pool).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection.as_mut()?)
        .await?;
    let query = tokio::spawn(async move {
        let outcome = sqlx::query("SELECT pg_sleep(30)")
            .execute(connection.as_mut()?)
            .await;
        connection.release().await;
        Ok::<_, sqlx::Error>(outcome.is_err())
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let active: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep')",
            )
            .bind(pid)
            .fetch_one(&mut observer)
            .await?;
            if active {
                break Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    cut.send(()).map_err(|_| "proxy cut lost")?;
    let failed = tokio::time::timeout(Duration::from_secs(3), query).await???;
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep')",
    )
    .bind(pid)
    .fetch_one(&mut observer)
    .await?;
    let closed = limit.is_closed();
    drop(lease);
    let refused = Admission::from_limit(&limit).is_err();
    // Finish owned suppliers before asserting either the positive or negative.
    sqlx::query("SELECT pg_cancel_backend($1)")
        .bind(pid)
        .execute(&mut observer)
        .await?;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(3), proxy).await???;
    observer.close().await?;
    tokio::time::timeout(Duration::from_secs(3), pool.close()).await?;
    assert!(
        failed && pending,
        "actual server work must outlive transport close"
    );
    assert!(
        closed && refused,
        "unconfirmed server completion must close admission"
    );
    Ok(())
}
