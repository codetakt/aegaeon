use super::*;
use std::{io::Write, net::TcpListener};

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual SETNAME lost reply precedes any authority command"]
async fn shared_redis_organizations_store_label_lost_reply_keeps_pending() -> TestResult {
    let witness = CallerFixture::new(Uuid::new_v4()).await?;
    let upstream = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let proxy = redis::Client::open(format!("redis://{}/", listener.local_addr()?))?;
    let actual = upstream.clone();
    let peer = std::thread::spawn(move || relay(listener, actual));
    let key = format!("work-label-{}", Uuid::new_v4());
    let requested = key.clone();
    let result: anyhow::Result<_> = async {
        let work = witness.begin().await?;
        let expected = work
            .admission()
            .store_label()?
            .ok_or_else(|| anyhow::anyhow!("missing attribution"))?
            .to_owned();
        let operation = work
            .blocking(move || -> redis::RedisResult<()> {
                let mut connection = crate::redis_io::connect(&proxy)?;
                redis::cmd("SET")
                    .arg(requested)
                    .arg("must-not-run")
                    .query(&mut connection)
            })
            .await?;
        let probe = work.admission().closure_probe_for_test();
        let completion = work.complete().await;
        Ok((
            expected,
            operation.is_err(),
            probe.is_closed(),
            completion.is_err(),
            witness.pending().await?,
        ))
    }
    .await;
    let observed = tokio::task::spawn_blocking(move || {
        peer.join()
            .map_err(|_| anyhow::anyhow!("label relay panicked"))?
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(std::convert::identity);
    // An old-code negative control may have performed SET. Remove only this
    // owned key after recording the outcome; leave its failure intact.
    let remove = tokio::task::spawn_blocking(move || -> redis::RedisResult<()> {
        let mut connection = upstream.get_connection_with_timeout(Duration::from_secs(3))?;
        connection.set_read_timeout(Some(Duration::from_secs(3)))?;
        connection.set_write_timeout(Some(Duration::from_secs(3)))?;
        redis::cmd("DEL").arg(key).query::<u64>(&mut connection)?;
        Ok(())
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|value| value.map_err(Into::into));
    let cleanup = witness.finish().await;
    let evaluated: TestResult = (|| {
        let (expected, failed, closed, incomplete, pending) = result?;
        let (observed, writes) = observed?;
        anyhow::ensure!(
            observed.as_deref() == Some(expected.as_str()),
            "actual Redis label was not installed"
        );
        anyhow::ensure!(
            writes == 0 && failed,
            "authority command ran before work attribution acknowledgement"
        );
        anyhow::ensure!(
            closed && incomplete && pending == 1,
            "uncertain attribution cleared its durable admission"
        );
        Ok(())
    })();
    evaluated.and(remove).and(cleanup)
}

fn relay(listener: TcpListener, upstream: redis::Client) -> anyhow::Result<(Option<String>, u32)> {
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                anyhow::ensure!(
                    std::time::Instant::now() < deadline,
                    "label relay accept deadline"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    };
    socket.set_read_timeout(Some(Duration::from_secs(8)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut actual = upstream.get_connection_with_timeout(Duration::from_secs(3))?;
    actual.set_read_timeout(Some(Duration::from_secs(3)))?;
    actual.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut parser = redis::Parser::new();
    let mut label = None;
    let mut writes = 0;
    while let Ok(redis::Value::Array(arguments)) = parser.parse_value(&mut socket) {
        let bytes: Vec<_> = arguments
            .iter()
            .map(|arg| match arg {
                redis::Value::BulkString(value) => Ok(value.as_slice()),
                _ => Err(anyhow::anyhow!("relay expected command bytes")),
            })
            .collect::<anyhow::Result<_>>()?;
        let Some(command) = bytes.first() else {
            anyhow::bail!("empty command");
        };
        if *command == b"CLIENT" && bytes.get(1).copied() == Some(b"SETNAME") {
            let name = bytes
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("missing name"))?;
            redis::cmd("CLIENT")
                .arg("SETNAME")
                .arg(*name)
                .query::<()>(&mut actual)?;
            label = redis::cmd("CLIENT").arg("GETNAME").query(&mut actual)?;
            // The real metadata mutation completed; suppress acknowledgement.
        } else if *command == b"SET" {
            let mut forwarded = redis::cmd("SET");
            for arg in bytes.iter().skip(1) {
                forwarded.arg(*arg);
            }
            forwarded.query::<()>(&mut actual)?;
            writes += 1;
            if label.is_none() {
                socket.write_all(b"+OK\r\n")?;
            }
        } else if label.is_none() {
            socket.write_all(if *command == b"PING" {
                b"+PONG\r\n"
            } else {
                b"+OK\r\n"
            })?;
        }
    }
    Ok((label, writes))
}
