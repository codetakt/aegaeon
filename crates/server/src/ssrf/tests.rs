use super::redirect::validate_redirect_target;
use super::resolver::resolve_host_for_outbound_client;
use super::*;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::sync::Arc;

type TestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_ok {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(value) => value,
            Err(err) => fail_test!("{}: {:?}", $context, err),
        }
    };
}

macro_rules! must_err {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(_) => fail_test!("{}", $context),
            Err(err) => err,
        }
    };
}

#[test]
fn blocks_loopback_v4() {
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(
        127, 255, 255, 255,
    ))));
}

#[test]
fn blocks_private_10() {
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(
        10, 255, 255, 255,
    ))));
}

#[test]
fn blocks_private_172_16() {
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(
        172, 31, 255, 255,
    ))));
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));
}

#[test]
fn blocks_private_192_168() {
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(
        192, 168, 255, 255,
    ))));
}

#[test]
fn blocks_link_local_and_cloud_metadata() {
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(
        169, 254, 169, 254,
    ))));
}

#[test]
fn blocks_cgnat() {
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(
        100, 127, 255, 255,
    ))));
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
}

#[test]
fn blocks_documentation() {
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
}

#[test]
fn blocks_benchmarking() {
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(
        198, 19, 255, 255,
    ))));
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(198, 20, 0, 1))));
}

#[test]
fn blocks_reserved_and_multicast() {
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(
        255, 255, 255, 254,
    ))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::BROADCAST)));
}

#[test]
fn blocks_this_host() {
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1))));
}

#[test]
fn allows_public_v4() {
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(
        93, 184, 216, 34,
    ))));
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(
        185, 199, 108, 153,
    ))));
}

#[test]
fn blocks_loopback_v6() {
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn blocks_unspecified_v6() {
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
}

#[test]
fn blocks_unique_local_v6() {
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0xfc00, 0, 0, 0, 0, 0, 0, 1,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0xfd00, 0, 0, 0, 0, 0, 0, 1,
    ))));
}

#[test]
fn blocks_link_local_v6() {
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0xfe80, 0, 0, 0, 0, 0, 0, 1,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0xfebf, 0xffff, 0, 0, 0, 0, 0, 1,
    ))));
}

#[test]
fn blocks_multicast_v6() {
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0xff02, 0, 0, 0, 0, 0, 0, 1,
    ))));
}

#[test]
fn blocks_ipv4_mapped_v6_private() {
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0xa9fe,
    ))));
}

#[test]
fn allows_public_v6() {
    assert!(!is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
    ))));
    assert!(!is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
    ))));
}

#[test]
fn ipv4_mapped_v6_public_allowed() {
    assert!(!is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808,
    ))));
}

#[test]
fn validate_url_blocks_loopback_literal() -> TestResult {
    let err = must_err!(
        validate_url_not_private("https://127.0.0.1/foo"),
        "loopback URL should be rejected",
    );
    assert!(matches!(err, SsrfError::NonRoutableIp(_)));
    Ok(())
}

#[test]
fn validate_url_blocks_private_10_literal() -> TestResult {
    let err = must_err!(
        validate_url_not_private("https://10.0.0.1/.well-known/openid-federation"),
        "private URL should be rejected",
    );
    assert!(matches!(err, SsrfError::NonRoutableIp(_)));
    Ok(())
}

#[test]
fn validate_url_blocks_private_192_168_literal() -> TestResult {
    let err = must_err!(
        validate_url_not_private("https://192.168.1.1/fetch?sub=x"),
        "private URL should be rejected",
    );
    assert!(matches!(err, SsrfError::NonRoutableIp(_)));
    Ok(())
}

#[test]
fn validate_url_blocks_link_local_literal() -> TestResult {
    let err = must_err!(
        validate_url_not_private("https://169.254.169.254/latest/meta-data/"),
        "link-local URL should be rejected",
    );
    assert!(matches!(err, SsrfError::NonRoutableIp(_)));
    Ok(())
}

#[test]
fn validate_url_blocks_v6_loopback_literal() -> TestResult {
    let err = must_err!(
        validate_url_not_private("https://[::1]/foo"),
        "loopback IPv6 URL should be rejected",
    );
    assert!(matches!(err, SsrfError::NonRoutableIp(_)));
    Ok(())
}

#[test]
fn validate_url_blocks_v6_unique_local_literal() -> TestResult {
    let err = must_err!(
        validate_url_not_private("https://[fc00::1]/foo"),
        "unique-local IPv6 URL should be rejected",
    );
    assert!(matches!(err, SsrfError::NonRoutableIp(_)));
    Ok(())
}

#[test]
fn validate_literal_host_blocks_localhost_without_dns() -> TestResult {
    let url = must_ok!(url::Url::parse("https://localhost/foo"), "url");
    let err = must_err!(
        validate_url_host_not_non_routable_literal(&url),
        "localhost URL should be rejected",
    );
    assert!(matches!(err, SsrfError::NonRoutableIp(_)));
    Ok(())
}

#[test]
fn validate_literal_host_blocks_bracketed_private_ipv6_without_dns() -> TestResult {
    let url = must_ok!(url::Url::parse("https://[fc00::1]/foo"), "url");
    let err = must_err!(
        validate_url_host_not_non_routable_literal(&url),
        "unique-local IPv6 URL should be rejected",
    );
    assert!(matches!(err, SsrfError::NonRoutableIp(_)));
    Ok(())
}

#[test]
fn validate_literal_host_allows_dns_name_without_resolving() -> TestResult {
    let url = must_ok!(url::Url::parse("https://idp.example.com/foo"), "url");
    must_ok!(
        validate_url_host_not_non_routable_literal(&url),
        "DNS names should be left to the outbound resolver",
    );
    Ok(())
}

#[test]
fn validate_url_invalid_url() -> TestResult {
    let err = must_err!(
        validate_url_not_private("not-a-url"),
        "invalid URL should be rejected",
    );
    assert!(matches!(err, SsrfError::InvalidUrl(_)));
    Ok(())
}

#[test]
fn validate_url_invalid_url_does_not_echo_input() -> TestResult {
    let raw = "not-a-url-with-secret-token";
    let err = must_err!(
        validate_url_not_private(raw),
        "invalid URL should be rejected",
    );
    let message = err.to_string();
    assert!(!message.contains(raw));
    assert!(!message.contains("secret-token"));
    Ok(())
}

#[test]
fn validate_url_allows_public_ip_literal() {
    assert!(validate_url_not_private("https://8.8.8.8/foo").is_ok());
}

#[test]
fn outbound_resolver_blocks_non_routable_ip_literal() -> TestResult {
    let err = must_err!(
        resolve_host_for_outbound_client("127.0.0.1"),
        "loopback DNS result must be rejected",
    );
    assert!(err.to_string().contains("non-routable"));
    Ok(())
}

#[test]
fn outbound_resolver_allows_public_ip_literal() -> TestResult {
    let addrs = must_ok!(
        resolve_host_for_outbound_client("8.8.8.8"),
        "public IP literal should resolve",
    );
    assert!(addrs
        .iter()
        .any(|addr| addr.ip() == IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    Ok(())
}

#[derive(Debug)]
struct PortZeroLoopbackResolver;

impl reqwest::dns::Resolve for PortZeroLoopbackResolver {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async {
            let addrs = vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))];
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[test]
fn reqwest_uses_url_port_when_resolver_addr_port_is_zero() -> TestResult {
    let listener = must_ok!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)),
        "bind loopback listener"
    );
    let port = must_ok!(listener.local_addr(), "listener address").port();
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 512];
        let _ = stream.read(&mut request)?;
        stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")?;
        stream.flush()
    });

    let client = must_ok!(
        reqwest::blocking::Client::builder()
            .dns_resolver(Arc::new(PortZeroLoopbackResolver))
            .build(),
        "reqwest client"
    );
    let response = must_ok!(
        client
            .get(format!("http://aegaeon-ssrf-port-zero.test:{port}/probe"))
            .send(),
        "port-zero resolver request"
    );
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(must_ok!(response.text(), "response body"), "ok");
    server
        .join()
        .map_err(|_| "mock server thread panicked".to_string())?
        .map_err(|err| format!("mock server failed: {err}"))?;
    Ok(())
}

#[test]
fn redirect_target_blocks_non_https() -> TestResult {
    let url = must_ok!(url::Url::parse("http://8.8.8.8/foo"), "url");

    let err = must_err!(
        validate_redirect_target(&url, None),
        "http redirect must be rejected",
    );
    assert!(err.contains("non-HTTPS"));
    Ok(())
}

#[test]
fn redirect_target_blocks_non_routable_ip_literal() -> TestResult {
    let url = must_ok!(url::Url::parse("https://127.0.0.1/foo"), "url");

    let err = must_err!(
        validate_redirect_target(&url, None),
        "loopback redirect must be rejected",
    );
    assert!(err.contains("non-routable"));
    Ok(())
}

#[test]
fn redirect_target_blocks_userinfo() -> TestResult {
    let url = must_ok!(
        url::Url::parse("https://user:secret@example.com/foo"),
        "url",
    );

    let err = must_err!(
        validate_redirect_target(&url, None),
        "userinfo-bearing redirect must be rejected",
    );
    assert!(err.contains("userinfo"));
    Ok(())
}

#[test]
fn redirect_target_fails_closed_on_dns_resolution_error() -> TestResult {
    let url = must_ok!(url::Url::parse("https://invalid.invalid/foo"), "url");

    let err = must_err!(
        validate_redirect_target(&url, None),
        "unresolved redirect must be rejected",
    );
    assert!(err.contains("DNS resolution failed"));
    Ok(())
}

#[test]
fn redirect_target_enforces_domain_allowlist() -> TestResult {
    let url = must_ok!(url::Url::parse("https://8.8.8.8/foo"), "url");
    let allowed = vec!["example.com".to_string()];

    let err = must_err!(
        validate_redirect_target(&url, Some(&allowed)),
        "off-allowlist redirect must be rejected",
    );
    assert!(err.contains("not in domain allowlist"));
    Ok(())
}

#[test]
fn cgnat_boundary_low() {
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(
        100, 63, 255, 255,
    ))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0))));
}

#[test]
fn cgnat_boundary_high() {
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(
        100, 127, 255, 255,
    ))));
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 0))));
}

#[test]
fn benchmarking_boundary() {
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(
        198, 17, 255, 255,
    ))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(
        198, 19, 255, 255,
    ))));
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(198, 20, 0, 0))));
}

#[test]
fn private_172_boundary() {
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(
        172, 15, 255, 255,
    ))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0))));
    assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(
        172, 31, 255, 255,
    ))));
    assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 0))));
}

#[test]
fn v6_unique_local_boundary() {
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0xfc00, 0, 0, 0, 0, 0, 0, 0,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    ))));
}

#[test]
fn v6_link_local_boundary() {
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0xfe80, 0, 0, 0, 0, 0, 0, 0,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0xfebf, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0xfec0, 0, 0, 0, 0, 0, 0, 1,
    ))));
}

#[test]
fn v6_special_use_boundaries() {
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0x0100, 0, 0, 0, 0, 0, 0, 1,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0x0064, 0xff9b, 0x0001, 0, 0, 0, 0, 1,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0, 0, 0, 0, 0, 0, 1,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x0002, 0, 0, 0, 0, 0, 1,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x0010, 0, 0, 0, 0, 0, 1,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x0db8, 0, 0, 0, 0, 0, 1,
    ))));
    assert!(is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0x2002, 0, 0, 0, 0, 0, 0, 1,
    ))));
    assert!(!is_non_routable(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
    ))));
}
