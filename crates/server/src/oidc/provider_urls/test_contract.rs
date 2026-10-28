//! Independent contract inventory, shared by signed and ordinary admission tests.
use serde_json::{json, Value};
pub(crate) const OP_ENDPOINTS: &[&str] = &[
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "end_session_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "pushed_authorization_request_endpoint",
    "device_authorization_endpoint",
];
pub(crate) const AS_ENDPOINTS: &[&str] = &[
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "pushed_authorization_request_endpoint",
    "device_authorization_endpoint",
];
pub(crate) const INFORMATIONAL: &[&str] = &["service_documentation", "op_policy_uri", "op_tos_uri"];
pub(crate) const OP_ALIASES: &[&str] = &[
    "token_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "pushed_authorization_request_endpoint",
    "registration_endpoint",
    "device_authorization_endpoint",
    "userinfo_endpoint",
];
pub(crate) const AS_ALIASES: &[&str] = &[
    "token_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "pushed_authorization_request_endpoint",
    "registration_endpoint",
    "device_authorization_endpoint",
];
pub(crate) const GOOD_ENDPOINTS: &[&str] = &[
    "https://provider.example",
    "HTTPS://Provider.example:8443/path?x=1",
    "https://other.example/?",
    "https://127.0.0.1:443/path",
];
pub(crate) fn bad_urls() -> Vec<Value> {
    vec![
        Value::Null,
        json!(true),
        json!(42),
        json!([]),
        json!({}),
        json!(""),
        json!("relative/path"),
        json!(" https://provider.example"),
        json!("https://provider.example/ "),
        json!("https://provider.example/\n"),
        json!("https://provider.example/\u{7f}"),
        json!("https://provider.example/\u{a0}"),
        json!("https://provider.example\\path"),
        json!("https://[invalid"),
    ]
}
pub(crate) fn bad_endpoints() -> Vec<Value> {
    let mut values = bad_urls();
    values.extend([
        json!("http://provider.example"),
        json!("urn:example:endpoint"),
        json!("https:provider.example"),
        json!("https:///provider.example"),
        json!("https://user:password@provider.example"),
        json!("https://@provider.example"),
        json!("https://provider.example/#fragment"),
        json!("https://provider.example/#"),
    ]);
    values
}
