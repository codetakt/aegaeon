use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn wait_capacity(expected: usize) -> TestResult {
    tokio::time::timeout(Duration::from_secs(3), async {
        while crate::web::browser_authorization_admission::available_for_test() != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}

async fn partial_form(address: SocketAddr, path: &str) -> TestResult<tokio::net::TcpStream> {
    let mut peer = tokio::net::TcpStream::connect(address).await?;
    peer.write_all(
        format!(
            "POST {path} HTTP/1.1\r\nHost: {address}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 1000\r\nConnection: close\r\n\r\nx"
        )
        .as_bytes(),
    )
    .await?;
    Ok(peer)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_browser_body_deadline_disconnect_and_recovery() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured(&f).await?;
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
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
        let uri = authorize(&state, &key)?;
        let (status, html) = page(&state, &sid, &uri, None).await?;
        assert_eq!(status, StatusCode::OK, "{html}");
        let token = transaction(&html)?.to_owned();

        // A disconnect before store work returns the slot without poisoning it.
        for path in ["/authorize", "/auth/consent"] {
            let peer = partial_form(address, path).await?;
            wait_capacity(7).await?;
            drop(peer);
            wait_capacity(8).await?;
        }
        let mut peers = Vec::new();
        for path in ["/authorize", "/auth/consent"].into_iter().cycle().take(8) {
            peers.push(partial_form(address, path).await?);
        }
        wait_capacity(0).await?;
        assert_eq!(
            page(&state, &sid, &uri, None).await?.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        // Keep every uploading peer open. The receiver's absolute deadline must
        // free capacity; neither an attacker EOF nor a response timeout suffices.
        tokio::time::timeout(Duration::from_secs(14), async {
            for peer in &mut peers {
                let mut response = Vec::new();
                let mut chunk = [0; 4096];
                while !response.windows(4).any(|s| s == b"\r\n\r\n") {
                    let count = peer.read(&mut chunk).await?;
                    if count == 0 || response.len() > 8192 {
                        return Err("incomplete or oversized response headers".into());
                    }
                    response.extend_from_slice(&chunk[..count]);
                }
                let headers = String::from_utf8(response)?.to_ascii_lowercase();
                assert!(headers.starts_with("http/1.1 503"), "{headers}");
                assert!(headers.contains("cache-control: no-store"), "{headers}");
            }
            TestResult::Ok(())
        })
        .await??;
        wait_capacity(8).await?;
        assert_eq!(page(&state, &sid, &uri, None).await?.0, StatusCode::OK);
        let (status, approved) = page(
            &state,
            &sid,
            "/auth/consent",
            Some(&[("transaction", &token), ("decision", "approve")]),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{approved}");
        assert!(code(&approved, &state.issuer).is_ok());
        Ok(())
    }
    .await;
    server.abort();
    let _ = server.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
