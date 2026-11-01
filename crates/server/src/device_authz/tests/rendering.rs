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

#[test]
fn device_confirmation_renderer_escapes_every_displayed_and_hidden_value() {
    let hostile = "<&\"'>";
    let escaped = "&lt;&amp;&quot;&#x27;&gt;";
    let html = render_confirm_page(hostile, hostile, hostile, Some(hostile), Some(hostile));
    assert!(!html.contains(hostile));
    assert_eq!(html.matches(escaped).count(), 8);
    assert!(html.contains("I have this device and its displayed code matches the code above."));
}

#[test]
fn device_confirmation_checkbox_is_unchecked_required_and_deny_is_independent() {
    let html = render_confirm_page("csrf", "ACDE-FGHJ", "client", None, None);
    let approve = html
        .split("action=\"/device/approve\"")
        .nth(1)
        .expect("approve form")
        .split("</form>")
        .next()
        .expect("approve form end");
    assert!(approve.contains(
        "type=\"checkbox\" id=\"confirm_device\" name=\"confirm_device\" value=\"yes\" required"
    ));
    assert!(!approve.contains("checked"));
    let deny = html
        .split("action=\"/device/deny\"")
        .nth(1)
        .expect("deny form")
        .split("</form>")
        .next()
        .expect("deny form end");
    assert!(!deny.contains("confirm_device"));
    assert!(!deny.contains("required"));
    assert!(deny.contains("name=\"csrf_token\" value=\"csrf\""));
    assert!(deny.contains("name=\"user_code\" value=\"ACDE-FGHJ\""));
}
