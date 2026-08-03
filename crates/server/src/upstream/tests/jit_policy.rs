use super::*;

#[test]
fn parse_upstream_jit_provisioning_policy_accepts_valid_policy() {
    let federation = json!({
        "jitProvisioning": {
            "enabled": true,
            "domainAllowlist": ["Example.com"],
            "collisionPolicy": "reuse_existing_email",
            "initialStatus": "BLOCKED"
        }
    });

    let policy = must_some(must_ok(parse_upstream_jit_provisioning_policy(Some(
        &federation,
    ))));

    assert!(policy.enabled);
    assert!(policy.require_verified_email);
    assert_eq!(policy.domain_allowlist, vec!["example.com".to_string()]);
    assert_eq!(
        policy.collision_policy,
        UpstreamJitProvisioningCollisionPolicy::ReuseExistingEmail
    );
    assert_eq!(
        policy.initial_status,
        UpstreamJitProvisioningInitialStatus::Blocked
    );
}

#[test]
fn parse_upstream_jit_provisioning_policy_rejects_invalid_domain() {
    let federation = json!({
        "jitProvisioning": {
            "enabled": true,
            "domainAllowlist": ["bad domain"]
        }
    });

    assert!(parse_upstream_jit_provisioning_policy(Some(&federation)).is_err());
}

#[test]
fn parse_upstream_jit_provisioning_policy_rejects_invalid_collision_policy() {
    let federation = json!({
        "jitProvisioning": {
            "enabled": true,
            "collisionPolicy": "merge"
        }
    });

    assert!(parse_upstream_jit_provisioning_policy(Some(&federation)).is_err());
}

#[test]
fn parse_upstream_jit_provisioning_policy_rejects_invalid_initial_status() {
    let federation = json!({
        "jitProvisioning": {
            "enabled": true,
            "initialStatus": "DELETED"
        }
    });

    assert!(parse_upstream_jit_provisioning_policy(Some(&federation)).is_err());
}

#[test]
fn email_allowed_by_domain_allowlist_checks_normalized_domain() {
    assert!(email_allowed_by_domain_allowlist(
        Some("User@Example.com"),
        &["example.com".to_string()]
    ));
    assert!(!email_allowed_by_domain_allowlist(
        Some("user@other.example"),
        &["example.com".to_string()]
    ));
    assert!(!email_allowed_by_domain_allowlist(
        None,
        &["example.com".to_string()]
    ));
}
