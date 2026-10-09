mod protocol_fixture;
mod response_redaction;
mod revocation_cache;
mod userinfo;

use super::*;
use super::{
    authorization::authorization_code,
    wire::{apply_auth, nonce_challenge, WireResponse},
};
use crate::profile::{sha256, ClientAuth, ParPolicy};
use reqwest::{
    header::{HeaderMap, LOCATION, WWW_AUTHENTICATE},
    StatusCode, Url,
};
use std::{sync::Arc, time::Instant};

#[test]
fn public_constructor_revalidates_exact_target_and_profile_before_credentials() -> Result<()> {
    let target = "https://issuer.example.test";
    let profile = test_profile(ClientAuth::ClientSecretBasic);
    assert!(ScenarioExecutor::with_profile(target.into(), Some(profile.clone())).is_ok());
    assert!(ScenarioExecutor::with_profile("http://127.0.0.1:1".into(), None).is_ok());
    assert!(ScenarioExecutor::with_profile(
        "https://other.example.test".into(),
        Some(profile.clone())
    )
    .is_err());
    let mut inactive = profile.clone();
    inactive.supply.activation = "INACTIVE".into();
    assert!(ScenarioExecutor::with_profile(target.into(), Some(inactive)).is_err());
    let mut insecure = profile;
    insecure.supply.issuer = "http://127.0.0.1:1".into();
    assert!(
        ScenarioExecutor::with_profile(insecure.supply.issuer.clone(), Some(insecure)).is_err()
    );
    for target in [
        "https://@issuer.example.test",
        "https://issuer.example.test/\nsecret",
    ] {
        let error = ScenarioExecutor::with_profile(target.into(), None)
            .err()
            .context("expected unsafe URL rejection")?;
        assert!(!error.to_string().contains("secret"));
    }
    Ok(())
}

#[tokio::test]
async fn public_constructor_cannot_bypass_oidc_validation_before_http() -> Result<()> {
    for (scope, algorithm) in [
        (None, None),
        (Some("read"), Some("RS256")),
        (Some("openid"), None),
        (Some("openid"), Some("HS256")),
    ] {
        let mut profile = test_profile(ClientAuth::ClientSecretBasic);
        profile.supply.oidc_scope = scope.map(str::to_owned);
        profile.supply.id_token_alg = algorithm.map(str::to_owned);
        let mut executor =
            ScenarioExecutor::with_profile(profile.supply.issuer.clone(), Some(profile))?;
        assert!(executor.ensure_token(true).await.is_err());
        assert!(executor.cached_userinfo_access_token.is_none());
        assert_eq!(executor.take_accounting().attempts, 0);
    }
    Ok(())
}
use reqwest::header::HeaderValue;
fn test_profile(auth: ClientAuth) -> ClientProfile {
    let supply = serde_json::from_value(serde_json::json!({"issuer":"https://issuer.example.test",
        "environment_id":"e","configuration_version_id":"v","oauth_profile_id":"p","activation":"ACTIVE",
        "client_id":"client+ id","redirect_uri":"https://client.example.test/cb","client_auth":auth,
        "scope":"read","subject":"subject","sender_policy":"dpop","par_policy":"required"})).unwrap();
    ClientProfile {
        supply,
        secret: "secret+ %:é".into(),
        session_cookie: HeaderValue::from_static("aegaeon_auth_session=private"),
        profile_sha256: "a".repeat(64),
        session_provenance_sha256: "b".repeat(64),
    }
}
#[test]
fn explicit_auth_method_uses_one_wire_location_and_encodes_basic_once() {
    use base64::Engine;
    for auth in [ClientAuth::ClientSecretBasic, ClientAuth::ClientSecretPost] {
        let profile = test_profile(auth);
        let mut params = vec![("token".into(), "a+b %:é".into())];
        let request = apply_auth(
            &profile,
            Client::new().post("https://issuer.example.test/token"),
            &mut params,
        )
        .form(&params)
        .build()
        .unwrap();
        assert!(!request.headers().contains_key(reqwest::header::COOKIE));
        assert!(!request.headers().contains_key("Forwarded"));
        let form: Vec<_> =
            form_urlencoded::parse(request.body().unwrap().as_bytes().unwrap()).collect();
        if auth == ClientAuth::ClientSecretBasic {
            let header = &request.headers()[reqwest::header::AUTHORIZATION];
            assert!(header.is_sensitive());
            let encoded = header.to_str().unwrap().strip_prefix("Basic ").unwrap();
            let wire = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap();
            assert_eq!(wire, b"client%2B+id:secret%2B+%25%3A%C3%A9");
            assert_eq!(form.len(), 1);
        } else {
            assert!(!request
                .headers()
                .contains_key(reqwest::header::AUTHORIZATION));
            assert_eq!(form.iter().filter(|(k, _)| k == "client_secret").count(), 1);
            assert!(form
                .iter()
                .any(|(k, v)| k == "client_secret" && v == "secret+ %:é"));
            assert!(form
                .iter()
                .any(|(k, v)| k == "client_id" && v == "client+ id"));
        }
    }
}
#[tokio::test]
async fn client_records_302_without_following_or_contacting_callback() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };
    let issuer = TcpListener::bind("127.0.0.1:0").unwrap();
    let callback = TcpListener::bind("127.0.0.1:0").unwrap();
    callback.set_nonblocking(true).unwrap();
    let base = format!("http://{}", issuer.local_addr().unwrap());
    let destination = format!("http://{}/callback", callback.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = issuer.accept().unwrap();
        let mut bytes = [0; 4096];
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut bytes).unwrap();
            assert!(count > 0, "request ended before its headers");
            request.extend_from_slice(&bytes[..count]);
            assert!(
                request.len() <= 16 * 1024,
                "request headers exceed fixture bound"
            );
        }
        stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {destination}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    });
    let mut executor = ScenarioExecutor::with_profile(base.clone(), None).unwrap();
    let response = executor
        .send(
            "GET",
            "/authorize",
            executor.client.get(format!("{base}/authorize")),
        )
        .await
        .unwrap();
    thread.join().unwrap();
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(
        callback.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let accounting = executor.take_accounting();
    accounting.validate().unwrap();
    assert_eq!(accounting.attempts, 1);
}
#[test]
fn authorization_redirect_requires_bound_destination_unique_state_issuer_and_code() {
    let mut headers = HeaderMap::new();
    let redirect = "https://client.example.test/callback?fixed=1";
    let good = "https://client.example.test/callback?fixed=1&code=code&state=state&iss=https%3A%2F%2Fissuer.example.test";
    headers.insert(LOCATION, HeaderValue::from_str(good).unwrap());
    assert_eq!(
        authorization_code(
            StatusCode::FOUND,
            &headers,
            redirect,
            "state",
            "https://issuer.example.test"
        )
        .unwrap(),
        "code"
    );
    assert!(authorization_code(
        StatusCode::OK,
        &headers,
        redirect,
        "state",
        "https://issuer.example.test"
    )
    .is_err());
    for bad in [
        good.replace("fixed=1", "fixed=2"),
        good.replace("client.example.test", "evil.example.test"),
        good.replace("state=state", "state=state&state=state"),
        good.replace("code=code", "code=code&error=denied"),
        good.replace("state=state", "state=wrong"),
        good.replace("issuer.example.test", "other.example.test"),
        format!("{good}#fragment"),
    ] {
        headers.insert(LOCATION, HeaderValue::from_str(&bad).unwrap());
        assert!(authorization_code(
            StatusCode::FOUND,
            &headers,
            redirect,
            "state",
            "https://issuer.example.test"
        )
        .is_err());
    }
    headers.insert(LOCATION, HeaderValue::from_str(good).unwrap());
    headers.append(LOCATION, HeaderValue::from_str(good).unwrap());
    assert!(authorization_code(
        StatusCode::FOUND,
        &headers,
        redirect,
        "state",
        "https://issuer.example.test"
    )
    .is_err());
}
#[test]
fn authorization_redirect_retains_raw_registered_query_before_response() {
    let response = "code=code&state=state&iss=https%3A%2F%2Fissuer.example.test";
    for registered in [
        "https://client.example.test/callback",
        "https://client.example.test/callback?",
        "https://client.example.test/callback?fixed=one%20two&other=%2f%3D&flag&empty=",
        "https://client.example.test/callback?fixed=1&",
    ] {
        let separator = if registered.contains('?') { '&' } else { '?' };
        let location = format!("{registered}{separator}{response}");
        let mut headers = HeaderMap::new();
        headers.insert(LOCATION, HeaderValue::from_str(&location).unwrap());
        assert_eq!(
            authorization_code(
                StatusCode::FOUND,
                &headers,
                registered,
                "state",
                "https://issuer.example.test"
            )
            .unwrap(),
            "code"
        );
    }
}
#[test]
fn authorization_redirect_rejects_reencoded_reordered_or_extra_static_query() {
    let registered = "https://client.example.test/callback?fixed=one%20two&other=%2f%3D";
    let response = "code=code&state=state&iss=https%3A%2F%2Fissuer.example.test";
    let good_query = "fixed=one%20two&other=%2f%3D";
    for query in [
        format!("fixed=one+two&other=%2f%3D&{response}"),
        format!("fixed=one%20two&other=%2F%3D&{response}"),
        format!("other=%2f%3D&fixed=one%20two&{response}"),
        format!("fixed=changed&other=%2f%3D&{response}"),
        format!("{good_query}changed&{response}"),
        format!("{response}&{good_query}"),
        format!("{good_query}&fixed=one%20two&{response}"),
        format!("{good_query}&extra=1&{response}"),
        format!("{good_query}&{response}&other=%2f%3D"),
        format!("{good_query}&{response}&code=extra"),
        format!("{good_query}&{response}&state=state"),
        format!("{good_query}&{response}&error_description=unexpected"),
        format!("{good_query}&{response}&"),
        format!("{good_query}&&{response}"),
    ] {
        let location = format!("https://client.example.test/callback?{query}");
        let mut headers = HeaderMap::new();
        headers.insert(LOCATION, HeaderValue::from_str(&location).unwrap());
        assert!(
            authorization_code(
                StatusCode::FOUND,
                &headers,
                registered,
                "state",
                "https://issuer.example.test"
            )
            .is_err(),
            "accepted altered query: {query}"
        );
    }
}
#[test]
fn nonce_challenge_distinguishes_as400_and_rs401_and_requires_header() {
    let mut response = WireResponse {
        status: StatusCode::BAD_REQUEST,
        headers: HeaderMap::new(),
        body: br#"{"error":"use_dpop_nonce"}"#.to_vec(),
    };
    assert!(nonce_challenge(&response, false).is_err());
    response
        .headers
        .insert("DPoP-Nonce", HeaderValue::from_static("nonce"));
    assert_eq!(
        nonce_challenge(&response, false).unwrap(),
        Some("nonce".into())
    );
    assert_eq!(nonce_challenge(&response, true).unwrap(), None);
    response.status = StatusCode::UNAUTHORIZED;
    assert!(nonce_challenge(&response, true).is_err());
    response.headers.insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("DPoP error=\"use_dpop_nonce\""),
    );
    assert_eq!(
        nonce_challenge(&response, true).unwrap(),
        Some("nonce".into())
    );
    response
        .headers
        .append("DPoP-Nonce", HeaderValue::from_static("second"));
    assert!(nonce_challenge(&response, true).is_err());
}

#[derive(Clone, Copy, Debug)]
enum FixtureDelivery {
    Complete,
    Disconnect,
    Truncated,
}

struct FixtureReply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delivery: FixtureDelivery,
}

fn fixture_reply(status: u16, body: Vec<u8>) -> FixtureReply {
    FixtureReply {
        status,
        headers: Vec::new(),
        body,
        delivery: FixtureDelivery::Complete,
    }
}

fn http_fixture(
    steps: usize,
    handler: impl FnMut(usize, &str, &str) -> FixtureReply + Send + 'static,
) -> (String, std::thread::JoinHandle<()>) {
    wire_fixture(steps, handler, None)
}

fn tls_fixture(
    steps: usize,
    handler: impl FnMut(usize, &str, &str) -> FixtureReply + Send + 'static,
) -> (String, std::thread::JoinHandle<()>, Client) {
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let der = certificate.serialize_der().unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(der.clone())],
        key.into(),
    )
    .unwrap();
    let client = Client::builder()
        .add_root_certificate(reqwest::Certificate::from_der(&der).unwrap())
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let (base, thread) = wire_fixture(steps, handler, Some(Arc::new(config)));
    (base, thread, client)
}

trait FixtureStream: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> FixtureStream for T {}

fn wire_fixture(
    steps: usize,
    mut handler: impl FnMut(usize, &str, &str) -> FixtureReply + Send + 'static,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> (String, std::thread::JoinHandle<()>) {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let scheme = if tls.is_some() { "https" } else { "http" };
    let base = format!("{scheme}://{}", listener.local_addr().unwrap());
    let server_base = base.clone();
    let thread = std::thread::spawn(move || {
        for step in 0..steps {
            let deadline = Instant::now() + Duration::from_secs(5);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture request was not sent");
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream: Box<dyn FixtureStream> = match &tls {
                Some(config) => Box::new(rustls::StreamOwned::new(
                    rustls::ServerConnection::new(config.clone()).unwrap(),
                    stream,
                )),
                None => Box::new(stream),
            };
            let mut request = Vec::new();
            let mut bytes = [0; 4096];
            loop {
                let count = stream.read(&mut bytes).unwrap();
                assert!(count > 0, "fixture request ended prematurely");
                request.extend_from_slice(&bytes[..count]);
                assert!(request.len() <= 16 * 1024);
                if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..end]).unwrap();
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let reply = handler(step, std::str::from_utf8(&request).unwrap(), &server_base);
            let advertised_length = match reply.delivery {
                FixtureDelivery::Disconnect => continue,
                FixtureDelivery::Complete => reply.body.len(),
                FixtureDelivery::Truncated => reply.body.len().checked_add(1).unwrap(),
            };
            let mut headers = format!(
                "HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
                reply.status, advertised_length
            );
            for (name, value) in reply.headers {
                use std::fmt::Write as _;
                write!(headers, "{name}: {value}\r\n").unwrap();
            }
            stream.write_all(headers.as_bytes()).unwrap();
            stream.write_all(b"\r\n").unwrap();
            stream.write_all(&reply.body).unwrap();
        }
    });
    (base, thread)
}

fn fixture_profile(base: &str, oidc: bool) -> ClientProfile {
    let mut profile = test_profile(ClientAuth::ClientSecretBasic);
    profile.supply.issuer = base.to_owned();
    profile.supply.par_policy = ParPolicy::Optional;
    if oidc {
        profile.supply.oidc_scope = Some("openid".into());
        profile.supply.id_token_alg = Some("RS256".into());
    }
    profile
}

fn authorization_fixture_reply(request: &str, base: &str) -> (FixtureReply, Option<String>) {
    let path = request.split_whitespace().nth(1).unwrap();
    let url = Url::parse(&format!("{base}{path}")).unwrap();
    assert_eq!(url.path(), "/authorize");
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let mut redirect = Url::parse(&query["redirect_uri"]).unwrap();
    redirect
        .query_pairs_mut()
        .append_pair("code", "code")
        .append_pair("state", &query["state"])
        .append_pair("iss", base);
    let mut reply = fixture_reply(302, Vec::new());
    reply
        .headers
        .push(("Location".into(), redirect.to_string()));
    (reply, query.get("nonce").cloned())
}

fn fixture_token(oidc: bool, expiry: u64) -> serde_json::Value {
    serde_json::json!({"access_token":"token","token_type":"DPoP","expires_in":expiry,
        "scope":if oidc { "openid" } else { "read" }})
}

#[tokio::test]
async fn discovery_requires_advertised_jwks_and_exact_issuer_and_token_endpoint() {
    for changed in [
        None,
        Some("issuer"),
        Some("token_endpoint"),
        Some("jwks_uri"),
        Some("alias"),
    ] {
        let (base, thread) = http_fixture(1, move |_, request, base| {
            assert!(request.starts_with("GET /.well-known/oauth-authorization-server "));
            let mut metadata = serde_json::json!({"issuer":base,"token_endpoint":format!("{base}/token"),"jwks_uri":format!("{base}/jwks")});
            if let Some(field) = changed {
                if field == "alias" {
                    metadata["jwks_uri"] = format!("{base}/.well-known/jwks.json").into();
                } else {
                    metadata[field] = "https://other.example.test/endpoint".into();
                }
            }
            fixture_reply(200, serde_json::to_vec(&metadata).unwrap())
        });
        let mut executor = ScenarioExecutor::with_profile(base, None).unwrap();
        assert_eq!(executor.discovery_flow().await.is_ok(), changed.is_none());
        thread.join().unwrap();
        let accounting = executor.take_accounting();
        accounting.validate().unwrap();
        assert_eq!(accounting.attempts, 1);
    }
}

#[tokio::test]
async fn discovery_http_transport_checks_independent_https_issuer_and_endpoints() {
    for changed in [
        None,
        Some("issuer"),
        Some("token_endpoint"),
        Some("jwks_uri"),
    ] {
        let canonical = "https://issuer.example.test/tenant";
        let (base, thread) = http_fixture(1, move |_, request, _| {
            assert!(request.starts_with("GET /.well-known/oauth-authorization-server "));
            let mut metadata = serde_json::json!({"issuer":canonical,
                "token_endpoint":format!("{canonical}/token"),
                "jwks_uri":format!("{canonical}/jwks")});
            if let Some(field) = changed {
                metadata[field] = "https://other.example.test/endpoint".into();
            }
            fixture_reply(200, serde_json::to_vec(&metadata).unwrap())
        });
        let prototype = ScenarioExecutor::for_scenario_with_discovery_issuer(
            base,
            &TestScenario::Discovery,
            Some(canonical),
        )
        .unwrap();
        let mut executor = prototype.fork_worker();
        assert_eq!(executor.discovery_flow().await.is_ok(), changed.is_none());
        thread.join().unwrap();
        let accounting = executor.take_accounting();
        accounting.validate().unwrap();
        assert_eq!(accounting.attempts, 1);
    }
}

#[test]
fn discovery_canonical_issuer_rejects_unsafe_urls_and_preserves_credential_target() {
    for issuer in [
        "http://issuer.example.test",
        "https://issuer.example.test/",
        "https://user:secret@issuer.example.test",
        "https://issuer.example.test?query",
        "https://issuer.example.test#fragment",
        "https://ISSUER.example.test",
        "not-a-url",
    ] {
        assert!(ScenarioExecutor::for_scenario_with_discovery_issuer(
            "http://127.0.0.1:18095".into(),
            &TestScenario::Discovery,
            Some(issuer),
        )
        .is_err());
    }
    let profile = fixture_profile("https://issuer.example.test", false);
    assert!(profile
        .supply
        .validate("https://issuer.example.test", false, false)
        .is_ok());
    for target in [
        "http://127.0.0.1:18095",
        "http://issuer.example.test",
        "https://other.example.test",
        "https://issuer.example.test/",
    ] {
        assert!(profile.supply.validate(target, false, false).is_err());
    }
}

#[tokio::test]
async fn standalone_jwks_digest_identifies_latest_success_or_failed_body() {
    let bodies = [
        (
            200,
            br#"{"keys":[{"kty":"oct","k":"AQAB"}]}"#.to_vec(),
            true,
        ),
        (503, b"unavailable".to_vec(), false),
        (200, b"invalid JSON".to_vec(), false),
        (200, br#"{"keys":[]}"#.to_vec(), true),
    ];
    let expected: Vec<_> = bodies
        .iter()
        .map(|(_, body, success)| (sha256(body), *success))
        .collect();
    let (base, thread) = http_fixture(bodies.len(), move |index, request, _| {
        assert!(request.starts_with("GET /.well-known/jwks.json "));
        fixture_reply(bodies[index].0, bodies[index].1.clone())
    });
    let mut executor = ScenarioExecutor::with_profile(base, None).unwrap();
    executor.jwks_sha256 = Some(sha256(b"previous accepted body"));
    for (digest, success) in expected {
        assert_eq!(executor.jwks_flow().await.is_ok(), success);
        assert_eq!(executor.jwks_sha256.as_deref(), Some(digest.as_str()));
    }
    thread.join().unwrap();
    let accounting = executor.take_accounting();
    accounting.validate().unwrap();
    assert_eq!(accounting.attempts, 4);
}

#[tokio::test]
async fn oidc_failure_records_received_jwks_before_status_or_verification() {
    for (status, body) in [
        (503, b"unavailable".to_vec()),
        (200, b"invalid JSON".to_vec()),
        (200, br#"{"keys":[]}"#.to_vec()),
    ] {
        let digest = sha256(&body);
        let (base, thread, client) = tls_fixture(3, move |step, request, base| match step {
            0 => authorization_fixture_reply(request, base).0,
            1 => {
                assert!(request.starts_with("POST /token "));
                let mut token = fixture_token(true, 300);
                token["id_token"] = "invalid.signature.token".into();
                fixture_reply(200, serde_json::to_vec(&token).unwrap())
            }
            _ => {
                assert!(request.starts_with("GET /.well-known/jwks.json "));
                fixture_reply(status, body.clone())
            }
        });
        let mut executor =
            ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, true)))
                .unwrap();
        executor.client = client;
        executor.jwks_sha256 = Some(sha256(b"previous accepted body"));
        assert!(executor.ensure_token(true).await.is_err());
        assert!(executor.cached_userinfo_access_token.is_none());
        assert_eq!(executor.jwks_sha256.as_deref(), Some(digest.as_str()));
        thread.join().unwrap();
        let accounting = executor.take_accounting();
        accounting.validate().unwrap();
        assert_eq!(accounting.attempts, 3);
    }
}

fn rsa_fixture_key() -> (jsonwebtoken::EncodingKey, Vec<u8>) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use std::{fs, process::Command};
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let directory = std::env::temp_dir().join(format!("aegaeon-loadtest-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let _cleanup = Cleanup(directory.clone());
    let key = directory.join("key.pem");
    let generated = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
        ])
        .arg(&key)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let modulus = Command::new("openssl")
        .args(["rsa", "-modulus", "-noout", "-in"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(modulus.status.success());
    let hex = String::from_utf8(modulus.stdout).unwrap();
    let hex = hex.trim().strip_prefix("Modulus=").unwrap();
    let bytes: Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let jwks = serde_json::to_vec(&serde_json::json!({"keys":[{"kty":"RSA","kid":"signing","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(bytes),"e":"AQAB"}]})).unwrap();
    (
        jsonwebtoken::EncodingKey::from_rsa_pem(&fs::read(key).unwrap()).unwrap(),
        jwks,
    )
}

#[tokio::test]
async fn token_deadline_includes_nonce_retry_and_delayed_jwks_without_stale_reuse() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let (key, jwks) = rsa_fixture_key();
    let expected_digest = sha256(&jwks);
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut nonce = String::new();
    let (base, thread, client) = tls_fixture(7, move |step, request, base| match step {
        0 | 4 => {
            let (reply, received_nonce) = authorization_fixture_reply(request, base);
            nonce = received_nonce.unwrap();
            reply
        }
        1 => {
            assert!(request.starts_with("POST /token "));
            sender.send(Instant::now()).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            let mut reply = fixture_reply(400, br#"{"error":"use_dpop_nonce"}"#.to_vec());
            reply
                .headers
                .push(("DPoP-Nonce".into(), uuid::Uuid::new_v4().to_string()));
            reply
        }
        2 | 5 => {
            assert!(request.starts_with("POST /token "));
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let claims = serde_json::json!({"iss":base,"sub":"subject","aud":"client+ id","nonce":nonce,"iat":now,"exp":now+300});
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = Some("signing".into());
            let id = jsonwebtoken::encode(&header, &claims, &key).unwrap();
            let mut token = fixture_token(true, 1);
            token["id_token"] = id.into();
            fixture_reply(200, serde_json::to_vec(&token).unwrap())
        }
        _ => {
            assert!(request.starts_with("GET /.well-known/jwks.json "));
            if step == 3 {
                std::thread::sleep(Duration::from_millis(1200));
            }
            fixture_reply(200, jwks.clone())
        }
    });
    let mut executor =
        ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, true))).unwrap();
    executor.client = client;
    let error = executor.ensure_token(true).await.err().unwrap();
    let first_request = receiver.recv().unwrap();
    assert!(first_request + Duration::from_secs(1) <= Instant::now());
    assert!(error.to_string().contains("token expired before delivery"));
    assert!(executor.cached_userinfo_access_token.is_none());
    assert_eq!(
        executor.jwks_sha256.as_deref(),
        Some(expected_digest.as_str())
    );
    executor.accounting.validate().unwrap();
    assert_eq!(executor.accounting.attempts, 4);
    let replacement = executor.ensure_token(true).await.unwrap();
    assert!(replacement.expires > Instant::now());
    assert_eq!(replacement.subject.as_deref(), Some("subject"));
    assert!(executor.cached_userinfo_access_token.is_some());
    assert_eq!(
        executor.jwks_sha256.as_deref(),
        Some(expected_digest.as_str())
    );
    thread.join().unwrap();
    let accounting = executor.take_accounting();
    accounting.validate().unwrap();
    assert_eq!(accounting.attempts, 7);
    assert_eq!(accounting.nonce_challenges["authorization_server"], 1);
    assert_eq!(accounting.nonce_retries["authorization_server"], 1);
}

#[tokio::test]
async fn token_expiry_and_sender_scope_validation_remain_fatal() {
    for field in [
        "zero",
        "missing",
        "overflow",
        "token_type",
        "scope",
        "refresh_token",
        "access_token",
    ] {
        let (base, thread, client) = tls_fixture(2, move |step, request, base| {
            if step == 0 {
                return authorization_fixture_reply(request, base).0;
            }
            assert!(request.starts_with("POST /token "));
            let mut token = fixture_token(false, 300);
            match field {
                "zero" => token["expires_in"] = 0.into(),
                "missing" => token
                    .as_object_mut()
                    .unwrap()
                    .remove("expires_in")
                    .map(|_| ())
                    .unwrap(),
                "overflow" => token["expires_in"] = u64::MAX.into(),
                "token_type" => token["token_type"] = "Bearer".into(),
                "scope" => token["scope"] = "other".into(),
                "refresh_token" => token["refresh_token"] = "unexpected".into(),
                _ => token["access_token"] = "".into(),
            }
            fixture_reply(200, serde_json::to_vec(&token).unwrap())
        });
        let mut executor =
            ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, false)))
                .unwrap();
        executor.client = client;
        assert!(
            executor.ensure_token(false).await.is_err(),
            "accepted {field}"
        );
        assert!(executor.cached_access_token.is_none());
        thread.join().unwrap();
        let accounting = executor.take_accounting();
        accounting.validate().unwrap();
        assert_eq!(accounting.attempts, 2);
    }
}
