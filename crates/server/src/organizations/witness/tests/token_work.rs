use super::*;
use crate::organizations::{request_work, witness::work::Work};
use redis::ConnectionLike;
use std::io::Write;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; actual token mutation with lost acknowledgement"]
async fn shared_redis_organizations_witness_retains_uncertain_token_work() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = exercise(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn exercise(f: &mut Fixture) -> TestResult {
    let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let scope = Scope {
        environment_id: Uuid::new_v4(),
        deployment_id: Uuid::new_v4(),
    };
    let operation = Uuid::new_v4();
    let selected = selection();
    maintenance.initialize(scope, operation).await?;
    maintenance.prepare(scope, operation, 1, &selected).await?;
    maintenance
        .activate(scope, operation, 2, &selected.acceptance_sha256)
        .await?;
    let work = Work::begin(
        f.connect(Role::Runtime).await?,
        request_work::Admission::isolated_for_test()?,
        scope,
        &selected,
    )
    .await?;
    let normal = client.clone();
    work.blocking(move || -> redis::RedisResult<()> {
        let mut connection = crate::redis_io::connect(&normal)?;
        let key = format!("organization-witness:{}", Uuid::new_v4());
        let (value,): (String,) = redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(&key)
            .arg("value")
            .ignore()
            .cmd("GET")
            .arg(&key)
            .query(&mut connection)?;
        assert_eq!(value, "value");
        // A real NOSCRIPT then SCRIPT LOAD/EVALSHA remains a normal operation.
        let script = redis::Script::new(&format!(
            "-- {}\nreturn redis.call('DEL', KEYS[1])",
            Uuid::new_v4()
        ));
        let deleted: i64 = script.key(&key).invoke(&mut connection)?;
        assert_eq!(deleted, 1);
        assert!(connection.check_connection());
        Ok(())
    })
    .await??;
    assert_eq!(work.complete().await?.pending, 0);

    let work = Work::begin(
        f.connect(Role::Runtime).await?,
        request_work::Admission::isolated_for_test()?,
        scope,
        &selected,
    )
    .await?;
    let cancellation_client = client.clone();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    {
        let operation = work.blocking(move || -> redis::RedisResult<()> {
            let mut connection = crate::redis_io::connect(&cancellation_client)?;
            assert!(connection.check_connection());
            let _ = entered.send(());
            wait.recv_timeout(Duration::from_secs(5)).map_err(|_| {
                redis::RedisError::from((
                    redis::ErrorKind::ClientError,
                    "owned fixture gate expired",
                ))
            })?;
            assert!(connection.check_connection());
            Ok(())
        });
        tokio::pin!(operation);
        tokio::select! {
            result = &mut operation => anyhow::bail!("worker ended before cancellation: {result:?}"),
            result = started => result?,
        }
        // Drop the caller's future while the actual store worker is retained.
    }
    let mut completing = tokio::spawn(work.complete());
    let premature = tokio::time::timeout(Duration::from_millis(50), &mut completing).await;
    let pending = maintenance.current(scope).await?.pending;
    release.send(())?;
    let completed = match premature {
        Ok(result) => result??,
        Err(_) => tokio::time::timeout(Duration::from_secs(5), completing).await???,
    };
    assert_eq!(
        pending, 1,
        "cancelled caller must retain actual token worker"
    );
    assert_eq!(completed.pending, 0);

    let key = format!("organization-witness-lost-ack:{}", Uuid::new_v4());
    let key_for_command = key.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let proxy = redis::Client::open(format!("redis://{}/", listener.local_addr()?))?;
    let upstream = client.clone();
    let (observed, mutation) = tokio::sync::oneshot::channel();
    let peer = std::thread::spawn(move || -> anyhow::Result<u32> {
        let end = std::time::Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    anyhow::ensure!(std::time::Instant::now() < end, "proxy accept deadline");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error.into()),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(8)))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut actual = upstream.get_connection_with_timeout(Duration::from_secs(3))?;
        actual.set_read_timeout(Some(Duration::from_secs(3)))?;
        actual.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut parser = redis::Parser::new();
        let mut observed = Some(observed);
        let mut mutations = 0;
        while let Ok(redis::Value::Array(arguments)) = parser.parse_value(&mut socket) {
            let Some(redis::Value::BulkString(command)) = arguments.first() else {
                anyhow::bail!("proxy expected a command");
            };
            if command == b"SET" {
                let mut forwarded = redis::cmd("SET");
                for arg in arguments.iter().skip(1) {
                    let redis::Value::BulkString(bytes) = arg else {
                        anyhow::bail!("proxy argument")
                    };
                    forwarded.arg(bytes);
                }
                forwarded.query::<()>(&mut actual)?;
                mutations += 1;
                if let Some(observed) = observed.take() {
                    let _ = observed.send(());
                }
                // The real Redis mutation committed. Suppress its reply and
                // every later reply until the actual driver closes transport.
            } else if mutations == 0 {
                socket.write_all(if command == b"PING" {
                    b"+PONG\r\n"
                } else {
                    b"+OK\r\n"
                })?;
            }
        }
        Ok(mutations)
    });
    let work = Work::begin(
        f.connect(Role::Runtime).await?,
        request_work::Admission::isolated_for_test()?,
        scope,
        &selected,
    )
    .await?;
    let caller = tokio::spawn(async move {
        let outcome = work
            .blocking(move || -> redis::RedisResult<()> {
                let mut connection = crate::redis_io::connect(&proxy)?;
                redis::cmd("SET")
                    .arg(&key_for_command)
                    .arg("committed")
                    .query(&mut connection)
            })
            .await;
        let closed = work.admission().ensure_open().is_err();
        (outcome, closed, work.complete().await)
    });
    tokio::time::timeout(Duration::from_secs(5), mutation).await??;
    assert_eq!(maintenance.current(scope).await?.pending, 1);
    let (outcome, closed, completed) =
        tokio::time::timeout(Duration::from_secs(10), caller).await??;
    let mutations = tokio::task::spawn_blocking(move || {
        peer.join().map_err(|_| anyhow::anyhow!("proxy panicked"))?
    })
    .await??;
    let value = tokio::task::spawn_blocking(move || -> redis::RedisResult<Option<String>> {
        let mut actual = crate::redis_io::connect(&client)?;
        let value = redis::cmd("GET").arg(&key).query(&mut actual)?;
        redis::cmd("DEL").arg(&key).query::<i64>(&mut actual)?;
        Ok(value)
    })
    .await??;
    let pending = maintenance.current(scope).await?.pending;
    maintenance.close().await?;
    assert!(outcome?.is_err());
    assert_eq!(mutations, 1, "an uncertain mutation must not be retried");
    assert_eq!(value.as_deref(), Some("committed"));
    assert!(closed, "lost acknowledgement must close admission");
    assert!(
        completed.is_err(),
        "uncertain token mutation cannot complete durable work"
    );
    assert_eq!(pending, 1, "uncertain token work must remain pending");
    Ok(())
}
