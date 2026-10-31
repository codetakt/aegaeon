use super::*;
use std::io::Read;
use std::time::{Duration, Instant};

pub(super) fn stalled_replay(
    state: &mut AppState,
) -> TestResult<(
    tokio::sync::oneshot::Receiver<()>,
    std::thread::JoinHandle<()>,
)> {
    let (url, received, peer) = stalled_peer()?;
    let replay = crate::middleware::replay_store::RedisReplayStore::new_for_tests(&url)?;
    state.dpop = Arc::new(
        crate::middleware::DpopMiddleware::new(
            state.environment_id.to_string(),
            state.issuer.as_str(),
            Arc::new(replay),
            Duration::from_secs(360),
        )
        .with_native_verifier_for_tests(),
    );
    Ok((received, peer))
}

pub(super) fn stalled_peer() -> TestResult<(
    String,
    tokio::sync::oneshot::Receiver<()>,
    std::thread::JoinHandle<()>,
)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let url = format!("redis://{}/", listener.local_addr()?);
    let (sent, received) = tokio::sync::oneshot::channel();
    let peer = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "owned peer accept deadline");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("owned peer: {error}"),
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut bytes = [0; 4096];
        assert!(socket.read(&mut bytes).unwrap() > 0);
        let _ = sent.send(());
        // A real accepted TCP stream stalls AUTH/CLIENT setup. Expect EOF from
        // the owned driver; a peer-side timeout is a failed cleanup assertion.
        while socket.read(&mut bytes).unwrap() != 0 {}
    });
    Ok((url, received, peer))
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_stalled_replay_keeps_executor_live_and_recovers() -> TestResult
{
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&f).await?;
    let result = f
        .in_epoch(Box::pin(async {
            let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
            let (_, token) = issue(&f, &state, &key, PRIVILEGE).await?;
            let auth = format!("DPoP {token}");
            for cancel in [false, true] {
                let mut failed = state.clone();
                let (received, peer) = stalled_replay(&mut failed)?;
                let signed = proof(&failed, &key, &token, "GET", json!({}))?;
                let authorization = auth.clone();
                let started = Instant::now();
                let request = tokio::spawn(async move {
                    get(
                        &failed,
                        Method::GET,
                        PATH,
                        Some(&authorization),
                        Some(&signed),
                        "",
                    )
                    .await
                    .map_err(|error| error.to_string())
                });
                received.await?;
                // This test uses one async executor thread. Inline synchronous
                // verification blocks it for the five-second Redis timeout.
                assert!(
                    started.elapsed() < Duration::from_secs(2),
                    "proof I/O blocked the executor"
                );
                let mut leases = Vec::new();
                for _ in 0..3 {
                    leases.push(crate::organizations::request_work::Admission::try_acquire()?);
                }
                assert!(crate::organizations::request_work::Admission::try_acquire().is_err());
                if cancel {
                    request.abort();
                    assert!(request.await.unwrap_err().is_cancelled());
                    assert!(crate::organizations::request_work::Admission::try_acquire().is_err());
                } else {
                    let (status, _) =
                        tokio::time::timeout(Duration::from_secs(8), request).await???;
                    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                }
                drop(leases);
                tokio::task::spawn_blocking(move || peer.join().unwrap()).await?;
                crate::organizations::request_work::Admission::drain_for_test().await?;
                let signed = proof(&state, &key, &token, "GET", json!({}))?;
                assert_eq!(
                    get(&state, Method::GET, PATH, Some(&auth), Some(&signed), "")
                        .await?
                        .0,
                    StatusCode::OK
                );
            }
            Ok(())
        }))
        .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
