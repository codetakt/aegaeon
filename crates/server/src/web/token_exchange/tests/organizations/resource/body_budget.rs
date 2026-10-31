use super::*;
use crate::organizations::request_work::Admission;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn wait_capacity(expected: usize) -> TestResult {
    tokio::time::timeout(Duration::from_secs(3), async {
        while Admission::available_for_test() != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}

async fn partial_read(
    address: SocketAddr,
    method: &str,
    path: &str,
    chunked: bool,
) -> TestResult<tokio::net::TcpStream> {
    let mut peer = tokio::net::TcpStream::connect(address).await?;
    let framing = if chunked {
        "Transfer-Encoding: chunked"
    } else {
        "Content-Length: 1"
    };
    peer.write_all(
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {address}\r\n{framing}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await?;
    Ok(peer)
}

async fn headers(peer: &mut tokio::net::TcpStream) -> TestResult<String> {
    let mut response = Vec::new();
    let mut chunk = [0; 4096];
    while !response.windows(4).any(|s| s == b"\r\n\r\n") {
        let count = peer.read(&mut chunk).await?;
        if count == 0 || response.len() > 8192 {
            return Err("incomplete or oversized response headers".into());
        }
        response.extend_from_slice(&chunk[..count]);
    }
    Ok(String::from_utf8(response)?.to_ascii_lowercase())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_resource_body_deadline_disconnect_and_recovery() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&f).await?;
    let witness = Arc::new(
        crate::organizations::witness::tests::caller_fixture::CallerFixture::new(
            state.environment_id,
        )
        .await?,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = crate::web::build_router(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });
    let result = async {
        let identity = format!(
            "/organization-invitations/{}/{}/identity",
            f.organization.scope.domain_id,
            uuid::Uuid::new_v4()
        );
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (_, token) = witness
            .run(Box::pin(issue(&f, &state, &key, PRIVILEGE)))
            .await??;
        wait_capacity(4).await?;
        // Fixed-length disconnects return input-only leases without poisoning.
        for path in [PATH, identity.as_str()] {
            let peer = partial_read(address, "GET", path, false).await?;
            wait_capacity(3).await?;
            drop(peer);
            wait_capacity(4).await?;
        }
        // Neither GET nor HEAD may wait indefinitely for the first chunk.
        let mut peers = Vec::new();
        for path in [PATH, identity.as_str()] {
            for method in ["GET", "HEAD"] {
                peers.push(partial_read(address, method, path, true).await?);
            }
        }
        wait_capacity(0).await?;
        assert_eq!(
            get(&state, Method::GET, PATH, None, None, "").await?.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        tokio::time::timeout(Duration::from_secs(14), async {
            for peer in &mut peers {
                let response = headers(peer).await?;
                assert!(response.starts_with("http/1.1 503"), "{response}");
                assert!(response.contains("cache-control: no-store"), "{response}");
            }
            TestResult::Ok(())
        })
        .await??;
        wait_capacity(4).await?;
        for path in [PATH, identity.as_str()] {
            let mut peer = partial_read(address, "GET", path, true).await?;
            peer.write_all(b"1\r\nx\r\n0\r\n\r\n").await?;
            let response =
                tokio::time::timeout(Duration::from_secs(3), headers(&mut peer)).await??;
            assert!(response.starts_with("http/1.1 400"), "{response}");
            assert!(response.contains("cache-control: no-store"), "{response}");
            wait_capacity(4).await?;
        }
        for method in [Method::GET, Method::HEAD] {
            let signed = proof(&state, &key, &token, method.as_str(), json!({}))?;
            assert_eq!(
                get_admitted(
                    &witness,
                    &state,
                    method,
                    PATH,
                    Some(&format!("DPoP {token}")),
                    Some(&signed),
                    ""
                )
                .await?
                .0,
                StatusCode::OK
            );
        }
        let mut peer = partial_read(address, "GET", &identity, true).await?;
        peer.write_all(b"0\r\n\r\n").await?;
        let response = tokio::time::timeout(Duration::from_secs(3), headers(&mut peer)).await??;
        assert!(response.starts_with("http/1.1 200"), "{response}");
        Ok(())
    }
    .await;
    server.abort();
    let _ = server.await;
    let cleanup = Arc::try_unwrap(witness)
        .map_err(|_| "retained fixture")?
        .finish()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
    let result = result.and(cleanup);
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
