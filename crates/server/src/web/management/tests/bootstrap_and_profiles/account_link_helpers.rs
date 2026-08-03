
// ---------------------------------------------------------------
// P1: SHA-256 helpers
// ---------------------------------------------------------------

#[test]
fn sha256_hex_produces_correct_hash() {
    let hash = sha256_hex(b"hello");
    assert_eq!(hash.len(), 64);
    assert_eq!(
        hash,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[test]
fn normalize_account_link_upstream_subject_filter_trims_input() -> TestResult {
    let subject = normalize_account_link_upstream_subject_filter(Some("  upstream-subject  "))
        .ok_or_else(|| io::Error::other("subject"))?;
    assert_eq!(subject, "upstream-subject");
    Ok(())
}

#[test]
fn normalize_account_link_upstream_subject_filter_ignores_empty_input() {
    assert_eq!(
        normalize_account_link_upstream_subject_filter(Some("   ")),
        None
    );
    assert_eq!(normalize_account_link_upstream_subject_filter(None), None);
}

#[test]
fn resolve_account_link_refresh_token_action_not_required_without_moving_tokens() -> TestResult {
    assert_eq!(resolve_account_link_refresh_token_action(0, None)?, None);
    assert_eq!(
        resolve_account_link_refresh_token_action(0, Some(AccountLinkRefreshTokenHandling::Clear),)?,
        None
    );
    Ok(())
}

#[test]
fn resolve_account_link_refresh_token_action_requires_explicit_choice() -> TestResult {
    let Err(err) = resolve_account_link_refresh_token_action(1, None) else {
        return Err(io::Error::other("expected refresh token handling error").into());
    };
    assert!(err.contains("Stored upstream refresh token handling"));
    Ok(())
}

#[test]
fn resolve_account_link_refresh_token_action_accepts_clear_and_retain() -> TestResult {
    assert_eq!(
        resolve_account_link_refresh_token_action(2, Some(AccountLinkRefreshTokenHandling::Clear),)?,
        Some(AccountLinkRefreshTokenAction::Clear)
    );
    assert_eq!(
        resolve_account_link_refresh_token_action(
            1,
            Some(AccountLinkRefreshTokenHandling::Retain),
        )?,
        Some(AccountLinkRefreshTokenAction::Retain)
    );
    Ok(())
}

#[test]
fn account_link_candidate_without_subject_match_is_low_confidence() {
    let candidate = AccountLinkConflictCandidate {
        end_user: User {
            id: "user-1".to_string(),
            environment_id: "env-1".to_string(),
            subject: "local-user".to_string(),
            email: Some("local-user@example.com".to_string()),
            status: "ACTIVE".to_string(),
            created_at: "2026-04-22T00:00:00.000Z".to_string(),
            updated_at: "2026-04-22T00:00:00.000Z".to_string(),
        },
        match_reasons: vec!["email".to_string()],
        recommended: true,
    };

    assert!(account_link_candidate_is_low_confidence(Some(&candidate)));
    assert!(account_link_candidate_is_low_confidence(None));
}

#[test]
fn account_link_candidate_with_subject_match_is_not_low_confidence() {
    let candidate = AccountLinkConflictCandidate {
        end_user: User {
            id: "user-1".to_string(),
            environment_id: "env-1".to_string(),
            subject: "local-user".to_string(),
            email: Some("local-user@example.com".to_string()),
            status: "ACTIVE".to_string(),
            created_at: "2026-04-22T00:00:00.000Z".to_string(),
            updated_at: "2026-04-22T00:00:00.000Z".to_string(),
        },
        match_reasons: vec!["subject".to_string(), "email".to_string()],
        recommended: true,
    };

    assert!(!account_link_candidate_is_low_confidence(Some(&candidate)));
}

#[test]
fn resolve_account_link_low_confidence_handling_requires_explicit_choice() -> TestResult {
    let Err(err) = resolve_account_link_low_confidence_handling(true, None) else {
        return Err(io::Error::other("expected low-confidence handling error").into());
    };
    assert!(err.contains("Low-confidence account link handling"));
    assert_eq!(
        resolve_account_link_low_confidence_handling(false, None)?,
        None
    );
    Ok(())
}

#[test]
fn resolve_account_link_inactive_target_handling_requires_explicit_choice() -> TestResult {
    let Err(err) = resolve_account_link_inactive_target_handling(true, None) else {
        return Err(io::Error::other("expected inactive target handling error").into());
    };
    assert!(err.contains("Inactive target user handling"));
    assert_eq!(
        resolve_account_link_inactive_target_handling(
            true,
            Some(AccountLinkInactiveTargetHandling::AllowInactive),
        )?,
        Some(AccountLinkInactiveTargetHandling::AllowInactive)
    );
    Ok(())
}

#[test]
fn account_link_reassignment_audit_severity_warns_on_policy_overrides() {
    assert_eq!(
        account_link_reassignment_audit_severity(
            Some(AccountLinkRefreshTokenAction::Retain),
            None,
            None,
        ),
        "WARNING"
    );
    assert_eq!(
        account_link_reassignment_audit_severity(
            Some(AccountLinkRefreshTokenAction::Clear),
            Some(AccountLinkLowConfidenceHandling::AllowLowConfidence),
            None,
        ),
        "WARNING"
    );
    assert_eq!(
        account_link_reassignment_audit_severity(
            Some(AccountLinkRefreshTokenAction::Clear),
            None,
            Some(AccountLinkInactiveTargetHandling::AllowInactive),
        ),
        "WARNING"
    );
    assert_eq!(
        account_link_reassignment_audit_severity(None, None, None),
        "INFO"
    );
}

#[test]
fn sha256_array_produces_32_bytes() {
    let result = sha256_array(b"hello");
    assert_eq!(result.len(), 32);
    assert_eq!(result[0], 0x2c);
    assert_eq!(result[1], 0xf2);
}
