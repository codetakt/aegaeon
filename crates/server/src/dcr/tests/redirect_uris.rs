use super::*;
use quickcheck::TestResult;
use quickcheck_macros::quickcheck;

fn clean_segment(mut input: String) -> String {
    if input.is_empty() {
        return "cb".into();
    }
    input.retain(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if input.is_empty() {
        "cb".into()
    } else {
        if input.len() > 32 {
            input.truncate(32);
        }
        input
    }
}

#[test]
fn relative_redirect_uri_is_rejected() {
    let uris = vec!["/callback".to_string()];
    assert!(validate_redirect_uris(&uris).is_err());
}

#[test]
fn malformed_redirect_uri_error_does_not_echo_input() {
    let raw = "not-a-url-with-client-secret";
    let uris = vec![raw.to_string()];
    let err = validate_redirect_uris(&uris).expect_err("malformed URI must be rejected");
    assert!(!err.contains(raw));
    assert!(!err.contains("client-secret"));
}

#[test]
fn https_redirect_uri_is_accepted() {
    let uris = vec!["https://example.com/callback".to_string()];
    assert!(validate_redirect_uris(&uris).is_ok());
}

#[test]
fn loopback_ipv6_http_redirect_uri_is_accepted() {
    let uris = vec!["http://[::1]:3000/callback".to_string()];
    assert!(validate_redirect_uris(&uris).is_ok());
}

#[test]
fn non_loopback_http_is_rejected() {
    let uris = vec!["http://example.com/callback".to_string()];
    assert!(validate_redirect_uris(&uris).is_err());
}

#[test]
fn redirect_uri_with_userinfo_is_rejected() {
    let uris = vec!["https://user@example.com/callback".to_string()];
    assert!(validate_redirect_uris(&uris).is_err());
}

#[quickcheck]
fn redirect_uri_with_fragment_is_rejected(path: String) -> TestResult {
    let segment = clean_segment(path);
    let uri = format!("https://example.com/{segment}#frag");
    TestResult::from_bool(validate_redirect_uris(&[uri]).is_err())
}

#[quickcheck]
fn https_without_fragment_is_accepted(path: String) -> TestResult {
    let segment = clean_segment(path);
    let uri = format!("https://example.com/{segment}");
    TestResult::from_bool(validate_redirect_uris(&[uri]).is_ok())
}
