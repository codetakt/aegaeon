use super::*;
use crate::client_registry::{
    jwks_refresh::{refresh_jwks_with_state, JwksRefreshOutcome},
    jwks_validation::build_kid_fingerprints,
    jwks_validators::{DateContext, JwksValidators},
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

// Exactly two responses: an identifying 304, then a rejected-member conflict.
// The counter is observable after each acquisition, so an unconditional retry
// cannot masquerade as a successful revalidation.
fn revalidation_fixture(
    changed: Vec<u8>,
) -> (
    String,
    Arc<AtomicUsize>,
    std::thread::JoinHandle<Vec<String>>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let uri = format!("http://{}/jwks.json", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let observed = hits.clone();
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for (status, bytes) in [(304, Vec::new()), (200, changed)] {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "bounded revalidation fixture request"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("revalidation accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 8192, "bounded request headers");
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            requests.push(String::from_utf8(request).unwrap());
            observed.fetch_add(1, Ordering::SeqCst);
            let headers = format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nContent-Type: application/json\r\nCache-Control: max-age=300\r\nETag: \"mixed\"\r\nConnection: close\r\n\r\n",bytes.len());
            stream.write_all(headers.as_bytes()).unwrap();
            stream.write_all(&bytes).unwrap();
            stream.flush().unwrap();
        }
        requests
    });
    (uri, hits, server)
}

#[test]
fn jwk_mixed_successful_304_preserves_fingerprints_and_refuses_later_rejected_member_reuse() {
    let _env = env_lock().unwrap();
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    let (key, _) = material(Algorithm::RS256);
    let value =
        json!({"keys":[key,{"kty":"RSA","kid":"rejected","n":"AA","e":"AQAB","use":"enc"}]});
    let body: FetchedJwks = serde_json::from_value(value.clone()).unwrap();
    let map = build_kid_fingerprints(&body);
    assert_eq!(map.len(), 2);
    assert_eq!(body.keys.len(), 1);
    let mut changed = value;
    changed["keys"][1]["n"] = json!("AQ");
    let (uri, hits, server) = revalidation_fixture(serde_json::to_vec(&changed).unwrap());
    let registry = registry();
    let mut entry = cache_test_entry(body, Instant::now() - Duration::from_secs(1));
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::ETAG, HeaderValue::from_static("\"mixed\""));
    entry.validators = JwksValidators::from_headers(&headers, DateContext::capture());
    entry.effective_target = Some(uri.clone());
    let old_anchor = entry.guard.admitted_at;
    registry
        .jwks_state
        .inner
        .cache
        .lock()
        .unwrap()
        .insert(uri.clone(), entry);

    let Some(JwksRefreshOutcome::RevalidatedBody(revalidated)) =
        refresh_jwks_with_state(&registry.jwks_state, &registry.jwks_policy, &uri)
    else {
        panic!("matching returned ETag must successfully revalidate the owned mixed body");
    };
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "successful 304 must not trigger an unconditional fetch"
    );
    assert_eq!(build_kid_fingerprints(&revalidated), map);
    assert!(select_jwk(&revalidated, Some("rejected")).is_none());
    let renewed = registry
        .jwks_state
        .inner
        .cache
        .lock()
        .unwrap()
        .get(&uri)
        .unwrap()
        .clone();
    assert_eq!(renewed.guard.kid_fps, map);
    assert!(
        renewed.guard.admitted_at > old_anchor,
        "successful revalidation retains existing new-admission semantics"
    );
    assert!(renewed.guard.deadline > renewed.guard.admitted_at);

    // Only the ignored sibling changes. Its original fingerprint must still
    // participate in admission after successful revalidation.
    assert!(refresh_jwks_with_state(&registry.jwks_state, &registry.jwks_policy, &uri).is_none());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert!(request.starts_with("GET /jwks.json HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains("if-none-match: \"mixed\""));
    }
    let cache = registry.jwks_state.inner.cache.lock().unwrap();
    let current = cache.get(&uri).unwrap();
    assert_eq!(build_kid_fingerprints(&current.jwks), map);
    assert_eq!(current.guard.admitted_at, renewed.guard.admitted_at);
    assert_eq!(current.guard.deadline, renewed.guard.deadline);
}
