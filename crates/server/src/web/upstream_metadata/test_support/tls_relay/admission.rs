//! Test-only DNS substitution scoped to live, fixed loopback relay authorities.
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::rc::Rc;

thread_local! {
    static PORTS: RefCell<BTreeMap<u16, usize>> = const { RefCell::new(BTreeMap::new()) };
}

pub(super) struct AdmissionGuard {
    ports: BTreeSet<u16>,
    // Creation, use and cleanup must stay on the same test thread.
    _current_thread: PhantomData<Rc<()>>,
}

impl AdmissionGuard {
    pub(super) fn new(backends: &[SocketAddr]) -> Self {
        assert!(!backends.is_empty());
        assert!(backends.iter().all(|backend| backend.ip().is_loopback()));
        let ports: BTreeSet<_> = backends.iter().map(SocketAddr::port).collect();
        PORTS.with(|registered| {
            let mut registered = registered.borrow_mut();
            for port in &ports {
                *registered.entry(*port).or_default() += 1;
            }
        });
        Self {
            ports,
            _current_thread: PhantomData,
        }
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        PORTS.with(|registered| {
            let mut registered = registered.borrow_mut();
            for port in &self.ports {
                let count = registered.get_mut(port).expect("owned relay authority");
                *count -= 1;
                if *count == 0 {
                    registered.remove(port);
                }
            }
        });
    }
}

pub(in crate::web::upstream_metadata) fn is_fixture_target(url: &url::Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("example.com")
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url
            .port()
            .is_some_and(|port| PORTS.with(|registered| registered.borrow().contains_key(&port)))
}

#[test]
fn upstream_tls_dns_admission_is_exact_and_thread_local() -> super::super::TestResult {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let target = url::Url::parse(&format!(
        "https://example.com:{}/token?tenant=1",
        address.port()
    ))?;
    assert!(!is_fixture_target(&target));
    let relay = super::TlsRelay::new(address, "example.com")?;
    assert!(is_fixture_target(&target));
    let unregistered = std::net::TcpListener::bind("127.0.0.1:0")?;
    for value in [
        format!("http://example.com:{}/token", address.port()),
        format!("https://other.example:{}/token", address.port()),
        format!("https://example.com.evil:{}/token", address.port()),
        format!("https://127.0.0.1:{}/token", address.port()),
        format!(
            "https://example.com:{}/token",
            unregistered.local_addr()?.port()
        ),
        "https://example.com/token".to_string(),
        format!("https://user:password@example.com:{}/token", address.port()),
        format!("{target}#fragment"),
    ] {
        assert!(!is_fixture_target(&url::Url::parse(&value)?), "{value}");
    }
    let other_thread_target = target.clone();
    assert!(
        !std::thread::spawn(move || is_fixture_target(&other_thread_target))
            .join()
            .unwrap()
    );
    drop(relay);
    assert!(!is_fixture_target(&target));
    Ok(())
}

#[test]
fn upstream_tls_dns_admission_preserves_overlapping_lifetimes() -> super::super::TestResult {
    let first = std::net::TcpListener::bind("127.0.0.1:0")?;
    let second = std::net::TcpListener::bind("127.0.0.1:0")?;
    let a = first.local_addr()?;
    let b = second.local_addr()?;
    let target_a = url::Url::parse(&format!("https://example.com:{}", a.port()))?;
    let target_b = url::Url::parse(&format!("https://example.com:{}", b.port()))?;
    let relay_a = super::TlsRelay::new(a, "example.com")?;
    let relay_b = super::TlsRelay::for_backends(vec![a, a, b])?;
    assert!(is_fixture_target(&target_a) && is_fixture_target(&target_b));
    drop(relay_a);
    assert!(is_fixture_target(&target_a) && is_fixture_target(&target_b));
    drop(relay_b);
    assert!(!is_fixture_target(&target_a) && !is_fixture_target(&target_b));
    Ok(())
}

#[test]
fn upstream_tls_dns_admission_keeps_url_and_allowlist_checks() -> super::super::TestResult {
    use crate::web::upstream_metadata::validate_upstream_outbound_url;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let relay = super::TlsRelay::new(listener.local_addr()?, "example.com")?;
    let target = format!("{}/token?tenant=1", relay.endpoint);
    validate_upstream_outbound_url(&target, "token", &["example.com".into()])
        .map_err(anyhow::Error::msg)?;
    assert!(
        validate_upstream_outbound_url(&target, "token", &["other.example".into()])
            .unwrap_err()
            .contains("domain allowlist")
    );
    assert!(validate_upstream_outbound_url(&format!("{target}#fragment"), "token", &[]).is_err());
    assert!(validate_upstream_outbound_url(
        &target.replace("https://", "https://user:password@"),
        "token",
        &[]
    )
    .is_err());
    Ok(())
}

#[test]
fn upstream_tls_dns_admission_cleans_up_after_unwind() -> super::super::TestResult {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let target = url::Url::parse(&format!("https://example.com:{}", address.port()))?;
    let panic = std::panic::catch_unwind(|| {
        let _relay = super::TlsRelay::new(address, "example.com").unwrap();
        assert!(is_fixture_target(&target));
        panic!("exercise scoped fixture cleanup");
    });
    assert!(panic.is_err());
    assert!(!is_fixture_target(&target));
    Ok(())
}
