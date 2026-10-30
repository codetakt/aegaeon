//! Owned TLS fixture; only trust and DNS change, never production request policy.
use std::{
    cell::RefCell,
    io::{Read, Write},
    marker::PhantomData,
    net::{SocketAddr, TcpListener},
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
struct Trust {
    certificate: reqwest::Certificate,
    address: SocketAddr,
}
thread_local! {static TRUST:RefCell<Option<Trust>>=const {RefCell::new(None)};}
pub(super) fn configure(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    TRUST.with(|s| match s.borrow().as_ref() {
        Some(t) => builder
            .add_root_certificate(t.certificate.clone())
            .resolve("delivery.example.test", t.address)
            .http1_only(),
        None => builder,
    })
}

pub(crate) struct Fixture {
    pub(crate) received: Arc<Mutex<Vec<serde_json::Value>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
    _current_thread: PhantomData<Rc<()>>,
}
impl Fixture {
    pub(crate) fn new(
        status: u16,
        bytes: Vec<u8>,
        delay: Duration,
        wrong_name: bool,
    ) -> anyhow::Result<Self> {
        let mut ca = rcgen::CertificateParams::new(vec![]);
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.not_before = rcgen::date_time_ymd(2025, 1, 1);
        ca.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let ca = rcgen::Certificate::from_params(ca)?;
        let mut leaf = rcgen::CertificateParams::new(vec![if wrong_name {
            "wrong.example.test"
        } else {
            "delivery.example.test"
        }
        .into()]);
        leaf.not_before = rcgen::date_time_ymd(2025, 1, 1);
        leaf.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let leaf = rcgen::Certificate::from_params(leaf)?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.serialize_der_with_signer(&ca)?.into()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf.serialize_private_key_der()).into(),
        )?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let trust = Trust {
            certificate: reqwest::Certificate::from_der(&ca.serialize_der()?)?,
            address: listener.local_addr()?,
        };
        TRUST.with(|s| {
            assert!(s.borrow().is_none());
            *s.borrow_mut() = Some(trust);
        });
        let received = Arc::new(Mutex::new(Vec::new()));
        let records = received.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            serve(
                listener,
                Arc::new(config),
                &stopped,
                records,
                status,
                bytes,
                delay,
            )
        });
        Ok(Self {
            received,
            stop,
            thread: Some(thread),
            _current_thread: PhantomData,
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        TRUST.with(|s| *s.borrow_mut() = None);
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                assert_eq!(result.unwrap(), Ok(()));
            }
        }
    }
}

fn serve(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    stop: &AtomicBool,
    received: Arc<Mutex<Vec<serde_json::Value>>>,
    status: u16,
    body: Vec<u8>,
    delay: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !stop.load(Ordering::SeqCst) {
        if Instant::now() > deadline {
            return Err("TLS fixture lifetime exceeded".into());
        }
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            Err(_) => return Err("TLS fixture accept failed".into()),
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(12)))
            .map_err(|_| "fixture read timeout")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| "fixture write timeout")?;
        let session =
            rustls::ServerConnection::new(config.clone()).map_err(|_| "fixture TLS setup")?;
        let mut stream = rustls::StreamOwned::new(session, stream);
        let Some(input) = read(&mut stream)? else {
            continue;
        };
        received
            .lock()
            .map_err(|_| "fixture journal poisoned")?
            .push(input);
        std::thread::sleep(delay);
        let response=format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\nLocation: https://other.example.test/forbidden\r\n\r\n",body.len());
        // A timeout or peer cancellation may close an already recorded request.
        let _ = stream
            .write_all(response.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .and_then(|()| stream.flush());
    }
    Ok(())
}

fn read(stream: &mut impl Read) -> Result<Option<serde_json::Value>, String> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 8192 {
            return Err("fixture header bound".into());
        }
        let mut b = [0];
        if stream.read_exact(&mut b).is_err() {
            return Ok(None);
        }
        header.push(b[0]);
    }
    let header = String::from_utf8(header).map_err(|_| "fixture header encoding")?;
    if !header.starts_with("POST /envelopes HTTP/1.1\r\n") {
        return Err("fixture request target".into());
    }
    let size = header
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|n| n.parse::<usize>().ok())
        })
        .ok_or("fixture content length")?;
    if size > 8192 {
        return Err("fixture body bound".into());
    }
    let mut body = vec![0; size];
    stream
        .read_exact(&mut body)
        .map_err(|_| "fixture incomplete request")?;
    let mut value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| "fixture JSON")?;
    value["fixtureAuthorizationPresent"] = serde_json::json!(header
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("authorization: bearer ")));
    Ok(Some(value))
}
