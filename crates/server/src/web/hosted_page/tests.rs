use super::*;
use axum::body::to_bytes;

#[tokio::test]
async fn public_mail_landing_is_direct_self_contained_and_disables_caching() {
    let response = landing(
        "https://example.test",
        Uuid::from_u128(1),
        "opaque-csrf",
        42,
    );
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert!(headers.get(header::LOCATION).is_none());
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
    let csp = headers[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(csp.contains("script-src 'nonce-"));
    assert!(csp.contains("connect-src 'self'"));
    let nonce = csp
        .split("'nonce-")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap()
        .to_owned();
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("data-csrf=\"opaque-csrf\""));
    assert!(html.contains(r#"<meta name="referrer" content="no-referrer">"#));
    assert!(html.contains(r#"<link rel="icon" href="data:,">"#) && csp.contains("img-src data:"));
    assert!(html.contains(r#"<span class="brand-name">Aegaeon</span>"#));
    assert!(html.contains(&format!("<style nonce=\"{nonce}\">")));
    assert!(csp.contains(&format!("style-src 'nonce-{nonce}'")));
    assert!(!html.contains("<script src="));
}

#[tokio::test]
#[ignore = "requires Node, OpenSSL and AEGAEON_CHROMIUM"]
async fn hosted_browser_walkthrough() {
    use std::{
        io::Write,
        path::Path,
        process::{Command, Stdio},
    };
    let issuer = "https://issuer.example.test";
    let environment = Uuid::from_u128(1);
    let response = landing(issuer, environment, "synthetic-landing-csrf", 1_800_000_000);
    let headers: std::collections::BTreeMap<_, _> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
        .collect();
    let bytes = to_bytes(response.into_body(), 65_536).await.unwrap();
    let page = serde_json::json!({"headers":headers,"html":std::str::from_utf8(&bytes).unwrap()});
    let script = std::env::var_os("AEGAEON_HOSTED_BROWSER_TEST_SCRIPT").map_or_else(
        || {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/organizations/hosted_invitation_browser.mjs")
        },
        std::path::PathBuf::from,
    );
    let mut node = Command::new("node")
        .arg(script)
        .stdin(Stdio::piped())
        .spawn()
        .expect("Node for browser test");
    node.stdin
        .take()
        .unwrap()
        .write_all(page.to_string().as_bytes())
        .unwrap();
    assert!(node.wait().unwrap().success());
}
