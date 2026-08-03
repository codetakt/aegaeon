use serde_json::json;

fn local_login_identifier_kind(identifier: &str) -> &'static str {
    if identifier.contains('@') {
        "email"
    } else {
        "subject"
    }
}

pub(in crate::web) fn local_login_success_audit_data(identifier: &str) -> serde_json::Value {
    json!({
        "identifierKind": local_login_identifier_kind(identifier)
    })
}

pub(in crate::web) fn local_login_failure_audit_data(identifier: &str) -> serde_json::Value {
    json!({
        "identifierKind": local_login_identifier_kind(identifier),
        "reason": "invalid_credentials"
    })
}
