//! Isolated HTTPS regression fixture: local CONNECT requests only; never forwards.
use super::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(super) const ORIGINAL: &str = "https://1.1.1.1/jwks";
pub(super) const OTHER: &str = "https://8.8.8.8/next";

pub(super) fn body(kid: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"keys":[{
        "kty":"RSA", "kid":kid, "alg":"RS256", "n":crate::test_utils::jwk_usage::public_shape_modulus(if kid=="A" {"AA"} else {"AQ"}), "e":"AQAB"
    }]}))
    .unwrap()
}

pub(super) struct Step {
    pub status: u16,
    pub headers: Vec<(&'static str, Vec<u8>)>,
    pub body: Vec<u8>,
    pub before_response: Option<Box<dyn FnOnce() + Send>>,
    pub header_delay: Duration,
    pub chunks: Vec<(Duration, Vec<u8>)>,
    pub path_bodies: Vec<(&'static str, Vec<u8>)>,
}
impl Step {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            headers: vec![],
            before_response: None,
            header_delay: Duration::ZERO,
            chunks: vec![],
            path_bodies: vec![],
        }
    }
    pub fn header(mut self, name: &'static str, value: impl AsRef<[u8]>) -> Self {
        self.headers.push((name, value.as_ref().to_vec()));
        self
    }
    pub fn ok(kid: &str) -> Self {
        Self::new(200, body(kid)).header("Cache-Control", "max-age=0")
    }
    pub fn redirect(location: &str) -> Self {
        Self::new(302, vec![]).header("Location", location)
    }
    pub fn not_modified(tag: &str) -> Self {
        Self::new(304, vec![])
            .header("ETag", tag)
            .header("Cache-Control", "max-age=0")
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct Observation {
    pub connect: String,
    pub request: Vec<u8>,
    pub error: Option<String>,
}
impl Observation {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.request).into_owned()
    }
    pub fn header(&self, name: &str) -> Option<Vec<u8>> {
        self.request.split(|b| *b == b'\n').find_map(|line| {
            let index = line.iter().position(|b| *b == b':')?;
            let (key, value) = (&line[..index], &line[index + 1..]);
            if !key.eq_ignore_ascii_case(name.as_bytes()) {
                return None;
            }
            let value = value.strip_prefix(b" ").unwrap_or(value);
            Some(value.strip_suffix(b"\r").unwrap_or(value).to_vec())
        })
    }
}

fn read_headers(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= 8192 {
            return Err("fixture header cap".into());
        }
        let mut byte = [0];
        reader.read_exact(&mut byte).map_err(|e| e.to_string())?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}
fn write_response(writer: &mut impl Write, mut step: Step) -> Result<(), String> {
    if let Some(action) = step.before_response.take() {
        action();
    }
    std::thread::sleep(step.header_delay);
    if step.status == 0 {
        return Ok(());
    } // Explicit transport-close control, no HTTP response.
    let body_len = if step.chunks.is_empty() {
        step.body.len()
    } else {
        step.chunks.iter().map(|x| x.1.len()).sum()
    };
    let mut headers = format!(
        "HTTP/1.1 {} Fixture\r\nContent-Length: {body_len}\r\nConnection: close\r\n",
        step.status
    )
    .into_bytes();
    for (name, value) in step.headers {
        headers.extend_from_slice(name.as_bytes());
        headers.extend_from_slice(b": ");
        headers.extend_from_slice(&value);
        headers.extend_from_slice(b"\r\n");
    }
    headers.extend_from_slice(b"\r\n");
    writer.write_all(&headers).map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;
    if step.chunks.is_empty() {
        writer.write_all(&step.body).map_err(|e| e.to_string())?;
    } else {
        for (delay, bytes) in step.chunks {
            std::thread::sleep(delay);
            writer.write_all(&bytes).map_err(|e| e.to_string())?;
            writer.flush().map_err(|e| e.to_string())?;
        }
    }
    writer.flush().map_err(|e| e.to_string())
}

pub(super) struct Fixture {
    pub ca_path: PathBuf,
    pub observations: Arc<Mutex<Vec<Observation>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    _proxy: Vec<EnvVarGuard>,
    shutdown_error: Option<String>,
}
impl Fixture {
    pub fn new(steps: Vec<Step>, wrong_san: bool) -> Self {
        let expected = std::env::var("JWKS_TEST_NETNS")
            .expect("run scripts/validation/test_client_jwks_cache.py");
        assert_eq!(
            std::fs::read_link("/proc/self/ns/net")
                .unwrap()
                .to_string_lossy(),
            expected
        );
        let output =
            PathBuf::from(std::env::var_os("JWKS_TEST_DIR").expect("temporary fixture directory"));
        let id = Uuid::new_v4().to_string();
        let mut ca_params = rcgen::CertificateParams::new(vec![]);
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        ca_params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let ca = rcgen::Certificate::from_params(ca_params).unwrap();
        let ca_pem = ca.serialize_pem().unwrap();
        let sans = if wrong_san {
            vec!["9.9.9.9".to_owned()]
        } else {
            vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()]
        };
        let mut params = rcgen::CertificateParams::new(sans.clone());
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let leaf = rcgen::Certificate::from_params(params).unwrap();
        let leaf_der = leaf.serialize_der_with_signer(&ca).unwrap();
        let private =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.serialize_private_key_der()));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(leaf_der.clone())], private)
        .unwrap();
        let ca_path = output.join(format!("{id}-ca.pem"));
        std::fs::write(&ca_path, &ca_pem).unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let mut proxy_guards = vec![];
        for key in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            proxy_guards.push(EnvVarGuard::new(key, Some(&proxy)));
        }
        for key in ["NO_PROXY", "no_proxy"] {
            proxy_guards.push(EnvVarGuard::new(key, Some("")));
        }
        proxy_guards.push(EnvVarGuard::new("REQUEST_METHOD", None));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let observations = Arc::new(Mutex::new(vec![]));
        let thread_observations = observations.clone();
        let thread = std::thread::spawn(move || {
            let config = Arc::new(config);
            let mut steps = VecDeque::from(steps);
            let deadline = Instant::now() + Duration::from_secs(45);
            let mut accepted = 0;
            while !thread_stop.load(Ordering::SeqCst) {
                assert!(Instant::now() < deadline, "fixture lifetime bound");
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("fixture accept {e}"),
                };
                accepted += 1;
                assert!(accepted <= 64, "fixture accept bound");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let connect = read_headers(&mut stream).expect("bounded CONNECT");
                let connect = String::from_utf8(connect).expect("ASCII CONNECT");
                let first = connect.lines().next().unwrap();
                assert!(
                    matches!(
                        first,
                        "CONNECT 1.1.1.1:443 HTTP/1.1" | "CONNECT 8.8.8.8:443 HTTP/1.1"
                    ),
                    "undeclared CONNECT {first}"
                );
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .unwrap();
                stream.flush().unwrap();
                let connection = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut tls = rustls::StreamOwned::new(connection, stream);
                let mut observation = Observation {
                    connect,
                    request: vec![],
                    error: None,
                };
                match read_headers(&mut tls) {
                    Ok(request) => {
                        observation.request = request;
                        // Preserve the received request before any scripted action can panic.
                        let index = {
                            let mut records = thread_observations.lock().unwrap();
                            let index = records.len();
                            records.push(observation.clone());
                            index
                        };
                        let Some(mut step) = steps.pop_front() else {
                            thread_observations.lock().unwrap()[index].error =
                                Some("unexpected extra product request".into());
                            panic!("unexpected extra product request");
                        };
                        for (path, body) in &step.path_bodies {
                            if observation
                                .request
                                .starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes())
                            {
                                step.body = body.clone();
                            }
                        }
                        if let Err(error) = write_response(&mut tls, step) {
                            thread_observations.lock().unwrap()[index].error = Some(error);
                        }
                        continue;
                    }
                    Err(error) => observation.error = Some(error),
                }
                thread_observations.lock().unwrap().push(observation);
            }
        });
        Self {
            ca_path,
            observations,
            stop,
            thread: Some(thread),
            _proxy: proxy_guards,
            shutdown_error: None,
        }
    }
    pub fn policy(&self) -> JwksRuntimePolicy {
        JwksRuntimePolicy {
            ca_bundle: Some(self.ca_path.clone()),
            allow_http_loopback_for_tests: false,
            insecure_skip_verify: false,
            http_retries: 0,
            http_timeout_secs: 3,
            circuit_open_fails: 10,
            log_sample_percent: 100,
            ..JwksRuntimePolicy::default()
        }
    }
    pub fn finish(mut self) -> Vec<Observation> {
        self.shutdown();
        assert!(
            self.shutdown_error.is_none(),
            "fixture teardown: {:?}",
            self.shutdown_error
        );
        self.observations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                self.shutdown_error = Some("fixture worker panicked".into());
            }
        }
        let _ = std::fs::remove_file(&self.ca_path);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(super) fn new_state() -> JwksRuntimeState {
    let state = JwksRuntimeState::default();
    *state.inner.last_gc.lock().unwrap() = Some(Instant::now());
    state
}
pub(super) fn kid(result: Option<FetchedJwks>) -> Option<String> {
    result
        .and_then(|jwks| jwks.keys.into_iter().next())
        .and_then(|key| key.kid)
}
