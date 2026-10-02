//! A fixture-owned CONNECT/TLS relay to one loopback HTTP listener. No forwarding
//! destination comes from a request. The client verifies the fixture certificate
//! and example.com hostname; production metadata and outbound checks are unchanged.
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

const LIMIT: usize = 2 * 1024 * 1024;

pub(crate) struct TlsRelay {
    pub client: reqwest::Client,
    pub endpoint: String,
    pub requests: Arc<AtomicUsize>,
    pub errors: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
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
    socket: TcpStream,
    backend: SocketAddr,
    config: Arc<rustls::ServerConfig>,
    requests: &AtomicUsize,
) -> Result<(), Box<dyn std::error::Error>> {
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut socket = socket;
    let connect = headers(&mut socket)?;
    let connect = std::str::from_utf8(&connect)?;
    if connect.lines().next()
        != Some(format!("CONNECT example.com:{} HTTP/1.1", backend.port()).as_str())
    {
        return Err("fixture CONNECT authority mismatch".into());
    }
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
        assert!(backend.ip().is_loopback());
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
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        if let Err(error) = relay(socket, backend, config.clone(), &observed) {
                            failures.lock().unwrap().push(error.to_string());
                        }
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
            endpoint: format!("https://example.com:{}", backend.port()),
            requests,
            errors,
            stop,
            thread: Some(thread),
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
fn upstream_tls_fixture_requires_scoped_trust_and_matching_hostname(
) -> super::super::ManagementTestResult {
    super::super::run(async {
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
