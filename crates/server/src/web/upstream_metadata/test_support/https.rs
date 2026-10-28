//! Current-thread, scoped HTTPS Discovery transport. No global environment override.
use std::cell::RefCell;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::net::{SocketAddr, TcpListener};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Trust {
    certificate: reqwest::Certificate,
    address: SocketAddr,
}

thread_local! {
    static TRUST: RefCell<Option<Trust>> = const { RefCell::new(None) };
}

pub(in crate::web) fn configure(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    TRUST.with(|slot| match slot.borrow().as_ref() {
        Some(trust) => builder
            .add_root_certificate(trust.certificate.clone())
            .resolve("upstream.example", trust.address)
            .no_proxy()
            .http1_only(),
        None => builder,
    })
}

// Substitute only the owned fixture's DNS preflight. URL/allowlist checks still
// run, and the HTTPS client verifies the fixture CA and upstream.example name.
pub(in crate::web::upstream_metadata) fn is_fixture_target(url: &url::Url) -> bool {
    TRUST.with(|slot| {
        slot.borrow().as_ref().is_some_and(|trust| {
            url.scheme() == "https"
                && url.host_str() == Some("upstream.example")
                && url.port() == Some(trust.address.port())
                && url.path() == "/issuer/.well-known/openid-configuration"
                && url.query().is_none()
        })
    })
}

pub(in crate::web) struct HttpsFixture {
    pub(in crate::web) issuer: String,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<Result<usize, String>>>,
    previous: Option<Trust>,
    // The scoped client configuration must be restored on its originating thread.
    _current_thread: PhantomData<Rc<()>>,
}

impl HttpsFixture {
    pub(in crate::web) fn new(mut body: serde_json::Value) -> anyhow::Result<Self> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let mut ca_params = rcgen::CertificateParams::new(vec![]);
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        ca_params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let ca = rcgen::Certificate::from_params(ca_params)?;
        let mut params = rcgen::CertificateParams::new(vec!["upstream.example".into()]);
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let leaf = rcgen::Certificate::from_params(params)?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf.serialize_der_with_signer(&ca)?)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.serialize_private_key_der())),
        )?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let trust = Trust {
            certificate: reqwest::Certificate::from_der(&ca.serialize_der()?)?,
            address: listener.local_addr()?,
        };
        let issuer = format!("https://upstream.example:{}/issuer", trust.address.port());
        body["issuer"] = serde_json::Value::String(issuer.clone());
        let body = serde_json::to_vec(&body)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = std::thread::spawn(move || {
            serve(listener, Arc::new(config), body, &stopped).map_err(|e| e.to_string())
        });
        let previous = TRUST.with(|slot| slot.replace(Some(trust)));
        Ok(Self {
            issuer,
            stop,
            worker: Some(worker),
            previous,
            _current_thread: PhantomData,
        })
    }

    pub(in crate::web) fn finish(mut self) -> anyhow::Result<()> {
        self.stop.store(true, Ordering::SeqCst);
        let count = self
            .worker
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing HTTPS worker"))?
            .join()
            .map_err(|_| anyhow::anyhow!("HTTPS fixture panicked"))?
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            count == 1,
            "expected exactly one Discovery fetch, got {count}"
        );
        Ok(())
    }
}

#[test]
fn upstream_https_fixture_dns_scope_is_exact_and_thread_local() -> anyhow::Result<()> {
    let fixture = HttpsFixture::new(serde_json::json!({}))?;
    let target = url::Url::parse(&format!(
        "{}/.well-known/openid-configuration",
        fixture.issuer
    ))?;
    assert!(is_fixture_target(&target));
    for value in [
        "http://upstream.example:1234/issuer/.well-known/openid-configuration",
        "https://upstream.example/issuer/.well-known/openid-configuration",
        "https://other.example/issuer/.well-known/openid-configuration",
        &format!("{}/other", fixture.issuer),
        &format!("{target}?other=1"),
    ] {
        assert!(!is_fixture_target(&url::Url::parse(value)?));
    }
    let other_thread_target = target.clone();
    assert!(
        !std::thread::spawn(move || is_fixture_target(&other_thread_target))
            .join()
            .unwrap()
    );
    drop(fixture);
    assert!(!is_fixture_target(&target));
    Ok(())
}

impl Drop for HttpsFixture {
    fn drop(&mut self) {
        TRUST.with(|slot| slot.replace(self.previous.take()));
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    body: Vec<u8>,
    stop: &AtomicBool,
) -> anyhow::Result<usize> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !stop.load(Ordering::SeqCst) {
        anyhow::ensure!(Instant::now() < deadline, "HTTPS fixture deadline");
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config)?, stream);
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            anyhow::ensure!(headers.len() < 8192, "HTTPS request header limit");
            let mut byte = [0];
            tls.read_exact(&mut byte)?;
            headers.push(byte[0]);
        }
        anyhow::ensure!(
            headers.starts_with(b"GET /issuer/.well-known/openid-configuration HTTP/1.1\r\n"),
            "unexpected HTTPS request target"
        );
        write!(tls, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
        tls.write_all(&body)?;
        tls.flush()?;
        return Ok(1);
    }
    Ok(0)
}
