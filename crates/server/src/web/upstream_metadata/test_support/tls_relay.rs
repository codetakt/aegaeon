//! A fixture-owned CONNECT/TLS relay to fixed loopback HTTP listeners. No forwarding
//! destination comes from a request. The client verifies the fixture certificate
//! and example.com hostname. A thread-local lifetime guard replaces DNS preflight
//! only for the relay's exact authorities; production outbound checks are unchanged.
mod admission;
pub(in crate::web::upstream_metadata) use admission::is_fixture_target;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

const LIMIT: usize = 2 * 1024 * 1024;

type ErrorRecordGate = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);

pub(crate) struct TlsRelay {
    pub client: reqwest::Client,
    pub endpoint: String,
    pub requests: Arc<AtomicUsize>,
    pub errors: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    _admission: admission::AdmissionGuard,
}

fn headers(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == 8192 {
            return Err(std::io::Error::other("fixture header limit"));
        }
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}

fn relay(
    socket: &mut TcpStream,
    backends: &[SocketAddr],
    config: Arc<rustls::ServerConfig>,
    requests: &AtomicUsize,
) -> Result<(), Box<dyn std::error::Error>> {
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let connect = headers(socket)?;
    let connect = std::str::from_utf8(&connect)?;
    let backend = backends
        .iter()
        .copied()
        .find(|backend| {
            connect.lines().next()
                == Some(format!("CONNECT example.com:{} HTTP/1.1", backend.port()).as_str())
        })
        .ok_or("fixture CONNECT authority mismatch")?;
    socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    let connection = rustls::ServerConnection::new(config)?;
    let mut tls = rustls::StreamOwned::new(connection, socket);
    let head = headers(&mut tls)?;
    let text = std::str::from_utf8(&head)?;
    let mut length = 0;
    let mut outgoing = Vec::new();
    for line in text.split("\r\n").filter(|line| !line.is_empty()) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err("fixture chunked request unsupported".into());
            }
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>()?;
            }
            if name.eq_ignore_ascii_case("connection") {
                continue;
            }
        }
        outgoing.extend_from_slice(line.as_bytes());
        outgoing.extend_from_slice(b"\r\n");
    }
    if length > LIMIT {
        return Err("fixture body limit".into());
    }
    outgoing.extend_from_slice(b"Connection: close\r\n\r\n");
    let mut body = vec![0; length];
    tls.read_exact(&mut body)?;
    outgoing.extend_from_slice(&body);
    requests.fetch_add(1, Ordering::SeqCst);
    let mut target = TcpStream::connect_timeout(&backend, Duration::from_secs(5))?;
    target.set_read_timeout(Some(Duration::from_secs(5)))?;
    target.set_write_timeout(Some(Duration::from_secs(5)))?;
    target.write_all(&outgoing)?;
    let mut response = Vec::new();
    target.take((LIMIT + 1) as u64).read_to_end(&mut response)?;
    if response.len() > LIMIT {
        return Err("fixture response limit".into());
    }
    tls.write_all(&response)?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
}

impl TlsRelay {
    pub fn new(
        backend: SocketAddr,
        certificate_name: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_trust(backend, certificate_name, true)
    }

    fn with_trust(
        backend: SocketAddr,
        certificate_name: &str,
        trusted: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_backends(vec![backend], certificate_name, trusted)
    }

    pub fn for_backends(backends: Vec<SocketAddr>) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_backends(backends, "example.com", true)
    }

    fn with_backends(
        backends: Vec<SocketAddr>,
        certificate_name: &str,
        trusted: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_error_record_gate(backends, certificate_name, trusted, None)
    }

    fn with_error_record_gate(
        backends: Vec<SocketAddr>,
        certificate_name: &str,
        trusted: bool,
        mut error_gate: Option<ErrorRecordGate>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        assert!(!backends.is_empty());
        assert!(backends.iter().all(|backend| backend.ip().is_loopback()));
        let endpoint = format!("https://example.com:{}", backends[0].port());
        let cert = rcgen::generate_simple_self_signed(vec![certificate_name.to_string()])?;
        let der = cert.serialize_der()?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.serialize_private_key_der()));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(der.clone())], key)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let builder = reqwest::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!(
                "http://{}",
                listener.local_addr()?
            ))?);
        let builder = if trusted {
            builder.add_root_certificate(reqwest::Certificate::from_der(&der)?)
        } else {
            builder
        };
        let client = builder
            .https_only(true)
            .http1_only()
            .pool_max_idle_per_host(0)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let failures = errors.clone();
        let config = Arc::new(config);
        let admission = admission::AdmissionGuard::new(&backends);
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        if let Err(error) = relay(&mut socket, &backends, config.clone(), &observed)
                        {
                            if let Some((reached, release)) = error_gate.take() {
                                reached.send(()).unwrap();
                                release.recv_timeout(Duration::from_secs(5)).unwrap();
                            }
                            failures.lock().unwrap().push(error.to_string());
                        }
                        // Publish the completed error record before EOF lets a
                        // rejected CONNECT request finish on the client thread.
                        drop(socket);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => {
                        failures.lock().unwrap().push(error.to_string());
                        break;
                    }
                }
            }
        });
        Ok(Self {
            client,
            endpoint,
            requests,
            errors,
            stop,
            thread: Some(thread),
            _admission: admission,
        })
    }
}

impl Drop for TlsRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[test]
fn upstream_tls_fixture_requires_scoped_trust_and_matching_hostname() -> super::TestResult {
    tokio::runtime::Runtime::new()?.block_on(async {
        for (name, trusted, allowed) in [
            ("example.com", true, true),
            ("wrong.example", true, false),
            ("example.com", false, false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let tls = TlsRelay::with_trust(listener.local_addr()?, name, trusted)?;
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let app = axum::Router::new().fallback(axum::routing::get(move || {
                observed.fetch_add(1, Ordering::SeqCst);
                async { "fixture" }
            }));
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let response = tls
                .client
                .get(format!("{}/health", tls.endpoint))
                .send()
                .await;
            assert_eq!(response.is_ok(), allowed);
            if let Ok(response) = response {
                assert_eq!(response.text().await?, "fixture");
                assert!(tls.errors.lock().unwrap().is_empty());
            }
            assert_eq!(tls.requests.load(Ordering::SeqCst), usize::from(allowed));
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(allowed));
            task.abort();
        }
        Ok(())
    })
}

#[test]
fn upstream_tls_fixture_routes_only_registered_backends() -> super::TestResult {
    tokio::runtime::Runtime::new()?.block_on(async {
        let mut listeners = Vec::new();
        let mut addresses = Vec::new();
        for _ in 0..2 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            addresses.push(listener.local_addr()?);
            listeners.push(listener);
        }
        let tls = TlsRelay::for_backends(addresses.clone())?;
        let mut tasks = Vec::new();
        for (index, listener) in listeners.into_iter().enumerate() {
            let app = axum::Router::new().fallback(axum::routing::get(move || async move {
                format!("backend-{index}")
            }));
            tasks.push(tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            }));
        }
        for (index, address) in addresses.iter().enumerate() {
            let body = tls
                .client
                .get(format!("https://example.com:{}/health", address.port()))
                .send()
                .await?
                .text()
                .await?;
            assert_eq!(body, format!("backend-{index}"));
        }
        assert_eq!(tls.requests.load(Ordering::SeqCst), 2);
        assert!(tls.errors.lock().unwrap().is_empty());
        let unregistered = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        for target in [
            format!(
                "https://example.com:{}/health",
                unregistered.local_addr()?.port()
            ),
            format!("https://other.example:{}/health", addresses[0].port()),
        ] {
            assert!(tls.client.get(target).send().await.is_err());
        }
        assert_eq!(tls.requests.load(Ordering::SeqCst), 2);
        let errors = tls.errors.lock().unwrap().clone();
        assert_eq!(errors, vec!["fixture CONNECT authority mismatch"; 2]);
        for task in tasks {
            task.abort();
        }
        Ok(())
    })
}

#[test]
fn upstream_tls_fixture_publishes_rejection_before_closing_socket() -> super::TestResult {
    tokio::runtime::Runtime::new()?.block_on(async {
        let backend = TcpListener::bind("127.0.0.1:0")?;
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let tls = TlsRelay::with_error_record_gate(
            vec![backend.local_addr()?],
            "example.com",
            true,
            Some((reached_tx, release_rx)),
        )?;
        let client = tls.client.clone();
        let target = format!(
            "https://other.example:{}/health",
            backend.local_addr()?.port()
        );
        let mut request = tokio::spawn(async move { client.get(target).send().await });
        tokio::task::spawn_blocking(move || reached_rx.recv_timeout(Duration::from_secs(5)))
            .await??;
        // Hold the actual worker between rejection and record publication.
        // The socket must remain open, so the client cannot observe EOF yet.
        let before_record = tokio::time::timeout(Duration::from_secs(1), &mut request).await;
        release_tx.send(())?;
        let remained_pending = before_record.is_err();
        if remained_pending {
            assert!(request.await?.is_err());
        }
        let failures = tls.errors.clone();
        assert_eq!(tls.requests.load(Ordering::SeqCst), 0);
        drop(tls); // Join the owned worker before assessing the final journal.
        let errors = failures.lock().unwrap().clone();
        assert_eq!(errors, vec!["fixture CONNECT authority mismatch"]);
        assert!(
            remained_pending,
            "client observed EOF before rejection was recorded"
        );
        Ok(())
    })
}
