use aegaeon_server::config::TransportSecurityConfig;
use aegaeon_server::middleware::tls::{TransportRejectionKind, TransportSecurity};
use http::{HeaderMap, HeaderValue};
use ipnet::IpNet;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

type TestResult = Result<(), String>;

trait TestContext<T> {
    fn test_context(self, context: &str) -> Result<T, String>;
}

impl<T, E: Display> TestContext<T> for Result<T, E> {
    fn test_context(self, context: &str) -> Result<T, String> {
        self.map_err(|err| format!("{context}: {err}"))
    }
}

impl<T> TestContext<T> for Option<T> {
    fn test_context(self, context: &str) -> Result<T, String> {
        self.ok_or_else(|| context.to_string())
    }
}

fn header_value(value: &str) -> Result<HeaderValue, String> {
    value.parse().test_context("parse header value")
}

fn result_err<T, E>(result: Result<T, E>, context: &str) -> Result<E, String> {
    result.err().test_context(context)
}

fn local_config() -> TransportSecurityConfig {
    TransportSecurityConfig {
        trusted_proxies: vec![IpNet::from(IpAddr::V4(Ipv4Addr::LOCALHOST))],
        require_tls_proxy: true,
        max_proxy_hops: 1,
        require_proxy_mtls: false,
        log_forwarded_values: false,
    }
}

fn localhost() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))
}

#[tokio::test]
async fn accepts_https_via_x_forwarded_proto() -> TestResult {
    let transport = TransportSecurity::new(local_config());
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-proto", header_value("https")?);
    assert!(transport.enforce(Some(localhost()), &headers).is_ok());
    Ok(())
}

#[tokio::test]
async fn rejects_duplicate_forwarded_header_fields() -> TestResult {
    let transport = TransportSecurity::new(local_config());
    let mut headers = HeaderMap::new();
    headers.append("forwarded", header_value("for=127.0.0.1;proto=https")?);
    headers.append("forwarded", header_value("for=127.0.0.1;proto=https")?);

    let err = result_err(
        transport.enforce(Some(localhost()), &headers),
        "expected duplicate Forwarded rejection",
    )?;
    assert_eq!(err, TransportRejectionKind::MalformedForwardedHeader);
    Ok(())
}

#[tokio::test]
async fn rejects_duplicate_x_forwarded_proto_header_fields() -> TestResult {
    let transport = TransportSecurity::new(local_config());
    let mut headers = HeaderMap::new();
    headers.append("x-forwarded-proto", header_value("https")?);
    headers.append("x-forwarded-proto", header_value("https")?);

    let err = result_err(
        transport.enforce(Some(localhost()), &headers),
        "expected duplicate X-Forwarded-Proto rejection",
    )?;
    assert_eq!(err, TransportRejectionKind::MalformedForwardedHeader);
    Ok(())
}

#[tokio::test]
async fn rejects_when_header_missing() -> TestResult {
    let transport = TransportSecurity::new(local_config());
    let headers = HeaderMap::new();
    let err = result_err(
        transport.enforce(Some(localhost()), &headers),
        "expected rejection",
    )?;
    assert_eq!(err, TransportRejectionKind::MissingForwardedHeader);
    Ok(())
}
