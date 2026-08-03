
#[test]
fn federation_logout_recovery_status_filter_accepts_known_status() -> TestResult {
    let Ok(value) = normalize_federation_logout_recovery_status_filter(Some("callback_rejected"))
    else {
        return Err(io::Error::other("expected valid status filter").into());
    };
    assert_eq!(value.as_deref(), Some("callback_rejected"));
    Ok(())
}

#[test]
fn federation_logout_recovery_status_filter_rejects_unknown_status() -> TestResult {
    let Err(error) = normalize_federation_logout_recovery_status_filter(Some("unknown")) else {
        return Err(io::Error::other("expected invalid status filter error").into());
    };
    assert!(error.contains("Invalid status filter"));
    Ok(())
}

#[test]
fn federation_logout_recovery_policy_filter_accepts_known_policy() -> TestResult {
    let Ok(value) = normalize_federation_logout_recovery_policy_filter(Some("disable_connection"))
    else {
        return Err(io::Error::other("expected valid recovery policy filter").into());
    };
    assert_eq!(value.as_deref(), Some("disable_connection"));
    Ok(())
}

#[test]
fn federation_logout_recovery_policy_filter_rejects_unknown_policy() -> TestResult {
    let Err(error) = normalize_federation_logout_recovery_policy_filter(Some("ignore")) else {
        return Err(io::Error::other("expected invalid recovery policy filter error").into());
    };
    assert!(error.contains("Invalid recoveryPolicy filter"));
    Ok(())
}

// ---------------------------------------------------------------
// P5: ISO 8601 timestamp validation
// ---------------------------------------------------------------

#[test]
fn is_valid_iso8601_accepts_standard_utc() {
    assert!(is_valid_iso8601("2026-01-15T00:00:00Z"));
}

#[test]
fn is_valid_iso8601_accepts_with_millis() {
    assert!(is_valid_iso8601("2026-01-15T12:30:45.123Z"));
}

#[test]
fn is_valid_iso8601_accepts_with_offset() {
    assert!(is_valid_iso8601("2026-01-15T12:30:45+09:00"));
}

#[test]
fn is_valid_iso8601_rejects_invalid_calendar_date() {
    assert!(!is_valid_iso8601("2026-02-30T00:00:00Z"));
    assert!(!is_valid_iso8601("2026-13-01T00:00:00Z"));
}

#[test]
fn is_valid_iso8601_rejects_invalid_time() {
    assert!(!is_valid_iso8601("2026-01-15T24:00:00Z"));
    assert!(!is_valid_iso8601("2026-01-15T12:60:00Z"));
    assert!(!is_valid_iso8601("2026-01-15T12:30:60Z"));
}

#[test]
fn is_valid_iso8601_rejects_missing_timezone() {
    assert!(!is_valid_iso8601("2026-01-15T12:30:45"));
}

#[test]
fn is_valid_iso8601_rejects_too_short() {
    assert!(!is_valid_iso8601("2026-01-15"));
}

#[test]
fn is_valid_iso8601_rejects_garbage() {
    assert!(!is_valid_iso8601("not-a-timestamp-at-all"));
}

#[test]
fn is_valid_iso8601_rejects_empty() {
    assert!(!is_valid_iso8601(""));
}

#[test]
fn is_valid_iso8601_rejects_oversized_fraction() {
    let timestamp = format!("2026-01-15T12:30:45.{}Z", "1".repeat(80));
    assert!(!is_valid_iso8601(&timestamp));
}

#[test]
fn is_valid_iso8601_rejects_date_only_with_space() {
    assert!(!is_valid_iso8601("2026-01-15 00:00:00"));
}

// ---------------------------------------------------------------
// P5: Audit filter SQL builder
// ---------------------------------------------------------------

#[test]
fn build_audit_filter_sql_no_filters() {
    let query = AuditEventListQuery {
        page_size: None,
        page_token: None,
        event_type: None,
        category: None,
        target_type: None,
        outcome: None,
        severity: None,
        from: None,
        to: None,
    };
    let (sql, idx) = build_audit_filter_sql(&query, 1);
    assert_eq!(sql, "");
    assert_eq!(idx, 1);
}

#[test]
fn build_audit_filter_sql_all_filters() {
    let query = AuditEventListQuery {
        page_size: None,
        page_token: None,
        event_type: Some("token.issued".to_string()),
        category: Some("AUTHENTICATION".to_string()),
        target_type: Some("CLIENT".to_string()),
        outcome: Some("SUCCESS".to_string()),
        severity: Some("INFO".to_string()),
        from: Some("2026-01-01T00:00:00Z".to_string()),
        to: Some("2026-01-31T23:59:59Z".to_string()),
    };
    let (sql, idx) = build_audit_filter_sql(&query, 1);
    assert!(sql.contains("AND event_type = $2"));
    assert!(sql.contains("AND category = $3"));
    assert!(sql.contains("AND target_type = $4"));
    assert!(sql.contains("AND outcome = $5"));
    assert!(sql.contains("AND severity = $6"));
    assert!(sql.contains("AND occurred_at >= $7::timestamptz"));
    assert!(sql.contains("AND occurred_at <= $8::timestamptz"));
    assert_eq!(idx, 8);
}

#[test]
fn build_audit_filter_sql_partial_filters() {
    let query = AuditEventListQuery {
        page_size: None,
        page_token: None,
        event_type: Some("client.created".to_string()),
        category: None,
        target_type: None,
        outcome: None,
        severity: None,
        from: Some("2026-01-01T00:00:00Z".to_string()),
        to: None,
    };
    let (sql, idx) = build_audit_filter_sql(&query, 1);
    assert!(sql.contains("AND event_type = $2"));
    assert!(sql.contains("AND occurred_at >= $3::timestamptz"));
    assert!(!sql.contains("category"));
    assert_eq!(idx, 3);
}

#[test]
fn build_audit_filter_sql_respects_base_bind_idx() {
    let query = AuditEventListQuery {
        page_size: None,
        page_token: None,
        event_type: Some("test".to_string()),
        category: None,
        target_type: None,
        outcome: None,
        severity: None,
        from: None,
        to: None,
    };
    let (sql, idx) = build_audit_filter_sql(&query, 3);
    assert!(sql.contains("AND event_type = $4"));
    assert_eq!(idx, 4);
}

// ---------------------------------------------------------------
// P5: CSV escape
// ---------------------------------------------------------------

#[test]
fn csv_escape_plain_text() {
    assert_eq!(csv_escape("hello"), "hello");
}

#[test]
fn csv_escape_with_comma() {
    assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
}

#[test]
fn csv_escape_with_quotes() {
    assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
}

#[test]
fn csv_escape_with_newline() {
    assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
}

#[test]
fn csv_escape_empty_string() {
    assert_eq!(csv_escape(""), "");
}

#[test]
fn csv_escape_neutralizes_formula_prefixes() {
    assert_eq!(csv_escape("=cmd"), "\"'=cmd\"");
    assert_eq!(csv_escape("+cmd"), "\"'+cmd\"");
    assert_eq!(csv_escape("-cmd"), "\"'-cmd\"");
    assert_eq!(csv_escape("@cmd"), "\"'@cmd\"");
    assert_eq!(csv_escape("\tcmd"), "\"'\tcmd\"");
    assert_eq!(csv_escape("\rcmd"), "\"'\rcmd\"");
    assert_eq!(csv_escape("\ncmd"), "\"'\ncmd\"");
    assert_eq!(csv_escape(" =cmd"), "\"' =cmd\"");
    assert_eq!(csv_escape(" \t@cmd"), "\"' \t@cmd\"");
    assert_eq!(csv_escape(" normal"), " normal");
}

// ---------------------------------------------------------------
// P5: Audit CSV export format
// ---------------------------------------------------------------

#[test]
fn audit_events_to_csv_empty_list() {
    let csv = audit_events_to_csv(&[]);
    assert!(csv.starts_with("id,"));
    assert_eq!(csv.lines().count(), 1); // header only
}

#[test]
fn audit_events_to_csv_single_event() {
    let event = AuditEvent {
        id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        team_id: "660e8400-e29b-41d4-a716-446655440000".to_string(),
        tenant_id: None,
        environment_id: Some("770e8400-e29b-41d4-a716-446655440000".to_string()),
        event_type: "token.issued".to_string(),
        category: "AUTHENTICATION".to_string(),
        outcome: "SUCCESS".to_string(),
        severity: "INFO".to_string(),
        occurred_at: "2026-01-15T10:30:00.000Z".to_string(),
        actor: AuditActor {
            actor_type: "CLIENT".to_string(),
            actor_id: Some("test-client".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: None,
            mfa: None,
        },
        target: AuditTarget {
            target_type: "ACCESS_TOKEN".to_string(),
            target_id: None,
        },
        request: AuditRequestContext {
            request_id: "req-123".to_string(),
            trace_id: None,
            span_id: None,
        },
        change: None,
        data: None,
    };
    let csv = audit_events_to_csv(&[event]);
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 2); // header + 1 data row
    assert!(lines[0].starts_with("id,"));
    assert!(lines[1].contains("550e8400"));
    assert!(lines[1].contains("token.issued"));
    assert!(lines[1].contains("SUCCESS"));
}

// ---------------------------------------------------------------
// P5: Export limits
// ---------------------------------------------------------------

#[test]
fn export_default_limit_is_1000() {
    assert_eq!(EXPORT_DEFAULT_LIMIT, 1000);
}

#[test]
fn export_max_limit_is_10000() {
    assert_eq!(EXPORT_MAX_LIMIT, 10000);
}
