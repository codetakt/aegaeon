use super::*;

#[test]
fn parse_upstream_logout_policy_accepts_valid_policy() {
    let federation = json!({
        "logout": {
            "backChannel": true,
            "sessionHintClaim": " sid ",
            "recoveryPolicy": "disable_connection"
        }
    });

    let policy = must_some(must_ok(parse_upstream_logout_policy(Some(&federation))));

    assert!(policy.back_channel);
    assert_eq!(policy.session_hint_claim.as_deref(), Some("sid"));
    assert_eq!(
        policy.recovery_policy,
        UpstreamLogoutRecoveryPolicy::DisableConnection
    );
}

#[test]
fn parse_upstream_logout_policy_rejects_missing_backchannel_boolean() {
    let federation = json!({
        "logout": {
            "sessionHintClaim": "sid"
        }
    });

    assert!(parse_upstream_logout_policy(Some(&federation)).is_err());
}

#[test]
fn parse_upstream_logout_policy_rejects_empty_session_hint_claim() {
    let federation = json!({
        "logout": {
            "backChannel": false,
            "sessionHintClaim": "   "
        }
    });

    assert!(parse_upstream_logout_policy(Some(&federation)).is_err());
}

#[test]
fn parse_upstream_logout_policy_defaults_recovery_policy() {
    let federation = json!({
        "logout": {
            "backChannel": false,
            "sessionHintClaim": "sid"
        }
    });

    let policy = must_some(must_ok(parse_upstream_logout_policy(Some(&federation))));

    assert_eq!(
        policy.recovery_policy,
        UpstreamLogoutRecoveryPolicy::ForcePromptLogin
    );
}

#[test]
fn parse_upstream_logout_policy_rejects_invalid_recovery_policy() {
    let federation = json!({
        "logout": {
            "backChannel": false,
            "recoveryPolicy": "ignore"
        }
    });

    assert!(parse_upstream_logout_policy(Some(&federation)).is_err());
}
