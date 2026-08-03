use super::*;

#[test]
fn default_policy_hardening_flags() {
    let policy = SecurityPolicy::default();

    assert!(policy.require_pkce);
    assert!(policy.enforce_trusted_proxy());
    assert!(policy.tls_validation_required());
    assert!(policy.require_scope_subset());
    assert!(policy.require_audience_match());
    assert!(policy.retain_refresh_chain());
    assert!(policy.enforce_sender_binding());
    assert_eq!(policy.sender_constrained, SenderConstraint::DPoP);
}

#[test]
fn policy_setters_are_functional_updates() {
    let base = SecurityPolicy::default();
    let updated = base
        .with_sender_constraint(SenderConstraint::Mtls)
        .with_sender_binding_enforcement(false);

    assert_eq!(base.sender_constrained, SenderConstraint::DPoP);
    assert!(base.enforce_sender_binding());
    assert_eq!(updated.sender_constrained, SenderConstraint::Mtls);
    assert!(!updated.enforce_sender_binding());
}
