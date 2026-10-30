use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual silent reply channel and production cleanup deadline"]
async fn pg_organizations_cleanup_deadline_closes_admission_on_silent_transport() -> TestResult {
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
    let (cut_ack, cut_observed) = oneshot::channel();
    let (stop, mut stop_rx) = tokio::sync::watch::channel(false);
    let mut stop_download = stop_rx.clone();
    let proxy = tokio::spawn(async move {
        let (client, _) = listener.accept().await?;
        let upstream = tokio::net::UnixStream::connect(socket).await?;
        let (mut client_read, mut client_write) = client.into_split();
        let (mut upstream_read, mut upstream_write) = upstream.into_split();
        let upload = async {
            tokio::select! {
                result = tokio::io::copy(&mut client_read, &mut upstream_write) => { result?; }
                _ = stop_rx.changed() => return Ok::<(), std::io::Error>(()),
            }
            let _ = stop_rx.changed().await;
            Ok(())
        };
        let download = async {
            tokio::select! {
                result = tokio::io::copy(&mut upstream_read, &mut client_write) => { result?; }
                _ = cut_rx => { let _ = cut_ack.send(()); }
            }
            // Retain both directions without sending EOF or ReadyForQuery.
            // Only the production cleanup deadline can end the wait normally.
            let _ = stop_download.changed().await;
            drop((upstream_read, client_write));
            Ok::<(), std::io::Error>(())
        };
        tokio::try_join!(upload, download)?;
        Ok::<(), std::io::Error>(())
    });
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
    let limit = Arc::new(Semaphore::new(1));
    let lease = Admission::from_limit(&limit)?;
    let connection = lease.connection(&pool).await?;
    cut.send(()).map_err(|_| "proxy cut lost")?;
    tokio::time::timeout(Duration::from_secs(3), cut_observed).await??;
    let started = tokio::time::Instant::now();
    let mut cleanup = tokio::spawn(connection.release());
    let ended = tokio::time::timeout(Duration::from_secs(35), &mut cleanup).await;
    let finished_before_rescue = ended.is_ok();
    let closed_before_rescue = limit.is_closed();
    let elapsed = started.elapsed();
    // Rescue the negative control without hiding its original missing deadline.
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(3), proxy).await???;
    match ended {
        Ok(result) => result?,
        Err(_) => tokio::time::timeout(Duration::from_secs(3), cleanup).await??,
    }
    drop(lease);
    tokio::time::timeout(Duration::from_secs(3), pool.close()).await?;
    assert!(
        finished_before_rescue && closed_before_rescue,
        "silent transport must end cleanup and close admission before rescue"
    );
    assert!(elapsed >= Duration::from_secs(30) && elapsed < Duration::from_secs(35));
    assert!(Admission::from_limit(&limit).is_err());
    Ok(())
}
