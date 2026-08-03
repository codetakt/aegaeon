use super::super::rendering::escape_html;
use super::*;

#[test]
fn render_user_code_form_contains_csrf() {
    let html = render_user_code_form("test-csrf-token", None, None);
    assert!(html.contains("test-csrf-token"));
    assert!(html.contains("user_code"));
    assert!(html.contains("Device Authorization"));
}

#[test]
fn render_user_code_form_prefills_code() {
    let html = render_user_code_form("csrf", Some("ABCD-EFGH"), None);
    assert!(html.contains("ABCD-EFGH"));
}

#[test]
fn render_user_code_form_shows_error() {
    let html = render_user_code_form("csrf", None, Some("Invalid code"));
    assert!(html.contains("Invalid code"));
}

#[test]
fn render_confirm_page_shows_client_and_scope() {
    let html = render_confirm_page(
        "csrf",
        "ABCD-EFGH",
        "my-client",
        Some("openid profile"),
        Some("https://api.example.com"),
    );
    assert!(html.contains("my-client"));
    assert!(html.contains("openid profile"));
    assert!(html.contains("https://api.example.com"));
    assert!(html.contains("ABCD-EFGH"));
    assert!(html.contains("/device/approve"));
    assert!(html.contains("/device/deny"));
}

#[test]
fn render_confirm_page_no_scope() {
    let html = render_confirm_page("csrf", "ABCD-EFGH", "my-client", None, None);
    assert!(html.contains("my-client"));
    assert!(!html.contains("Scope:"));
    assert!(!html.contains("Resource:"));
}

#[test]
fn render_result_page_content() {
    let html = render_result_page("Device Authorized", "You may close this window.");
    assert!(html.contains("Device Authorized"));
    assert!(html.contains("You may close this window."));
}

#[test]
fn escape_html_prevents_xss() {
    let result = escape_html("<script>alert('xss')</script>");
    assert!(!result.contains("<script>"));
    assert!(result.contains("&lt;script&gt;"));
}

#[test]
fn render_user_code_form_escapes_xss_in_prefill() {
    let html = render_user_code_form("csrf", Some("<img onerror=alert(1)>"), None);
    assert!(!html.contains("<img onerror"));
    assert!(html.contains("&lt;img"));
}
