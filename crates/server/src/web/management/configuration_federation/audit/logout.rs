use crate::upstream::parse_upstream_logout_policy;

pub(in crate::web::management) fn federation_logout_audit_snapshot(
    configuration_document: &serde_json::Value,
) -> serde_json::Value {
    match parse_upstream_logout_policy(configuration_document.get("federation"))
        .ok()
        .flatten()
    {
        Some(policy) => serde_json::json!({
            "managed": true,
            "backChannel": policy.back_channel,
            "sessionHintClaim": policy.session_hint_claim,
            "recoveryPolicy": policy.recovery_policy.as_str(),
        }),
        None => serde_json::json!({
            "managed": false,
        }),
    }
}

pub(in crate::web::management) fn federation_logout_audit_severity(
    snapshot: &serde_json::Value,
) -> &'static str {
    let managed = matches!(
        snapshot.get("managed").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let back_channel = matches!(
        snapshot
            .get("backChannel")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );

    if managed && !back_channel {
        "WARN"
    } else {
        "INFO"
    }
}
