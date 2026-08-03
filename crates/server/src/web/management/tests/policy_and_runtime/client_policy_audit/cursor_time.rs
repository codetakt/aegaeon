// ── Cursor-based pagination tests ──────────────────────────────────

#[test]
fn encode_decode_audit_cursor_roundtrip() -> TestResult {
    let ts = "2026-01-15T10:30:00.000Z";
    let id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    let token = encode_audit_cursor(ts, id);
    let (decoded_ts, decoded_id) = decode_audit_cursor(&token)
        .ok_or_else(|| io::Error::other("expected audit cursor to decode"))?;
    assert_eq!(decoded_ts, ts);
    assert_eq!(decoded_id.to_string(), id);
    Ok(())
}

#[test]
fn decode_audit_cursor_rejects_garbage() {
    assert!(decode_audit_cursor("not-valid-base64!!!").is_none());
}

#[test]
fn decode_audit_cursor_rejects_oversized_token() {
    assert!(decode_audit_cursor(&"a".repeat(512)).is_none());
}

#[test]
fn decode_audit_cursor_rejects_missing_pipe() {
    let token = URL_SAFE_NO_PAD.encode("no-pipe-separator");
    assert!(decode_audit_cursor(&token).is_none());
}

#[test]
fn decode_audit_cursor_rejects_invalid_uuid() {
    let token = URL_SAFE_NO_PAD.encode("2026-01-01T00:00:00Z|not-a-uuid");
    assert!(decode_audit_cursor(&token).is_none());
}

#[test]
fn decode_audit_cursor_rejects_invalid_timestamp() {
    let token = URL_SAFE_NO_PAD.encode("not-a-time|a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    assert!(decode_audit_cursor(&token).is_none());
}

#[test]
fn audit_cursor_from_page_token_rejects_invalid_timestamp() -> TestResult {
    let token = URL_SAFE_NO_PAD.encode("not-a-time|a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    let err = must_err!(
        audit_cursor_from_page_token(Some(&token), "req-1"),
        "invalid audit cursor timestamp must fail closed"
    );

    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[test]
fn audit_cursor_from_page_token_rejects_invalid_page_token() -> TestResult {
    let err = must_err!(
        audit_cursor_from_page_token(Some("not-valid-base64!!!"), "req-1"),
        "invalid audit pageToken must fail closed"
    );

    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

// ── approx_day_span tests ──────────────────────────────────────────

#[test]
fn approx_day_span_same_day() {
    let span = approx_day_span("2026-01-15T00:00:00Z", "2026-01-15T23:59:59Z");
    assert_eq!(span, Some(0));
}

#[test]
fn approx_day_span_one_day() {
    let span = approx_day_span("2026-01-15T00:00:00Z", "2026-01-16T00:00:00Z");
    assert_eq!(span, Some(1));
}

#[test]
fn approx_day_span_30_days() {
    let span = approx_day_span("2026-01-01T00:00:00Z", "2026-01-31T00:00:00Z");
    assert_eq!(span, Some(30));
}

#[test]
fn approx_day_span_90_days() {
    let span = approx_day_span("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z");
    // 3 months * 30 days/month = 90
    assert_eq!(span, Some(90));
}

#[test]
fn approx_day_span_invalid_date() {
    assert!(approx_day_span("garbage", "2026-01-01T00:00:00Z").is_none());
    assert!(approx_day_span("2026-01-01T00:00:00Z", "garbage").is_none());
}

#[test]
fn approx_day_span_rejects_reversed_range() {
    assert!(approx_day_span("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z").is_none());
}

// ── validate_audit_time_range tests ────────────────────────────────

#[test]
fn validate_audit_time_range_accepts_30_days() {
    let result = validate_audit_time_range("2026-01-01T00:00:00Z", "2026-01-31T00:00:00Z", "req-1");
    assert!(result.is_ok());
}

#[test]
fn validate_audit_time_range_accepts_90_days() {
    let result = validate_audit_time_range("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "req-2");
    assert!(result.is_ok());
}

#[test]
fn validate_audit_time_range_rejects_180_days() {
    let result = validate_audit_time_range("2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z", "req-3");
    assert!(result.is_err());
}

#[test]
fn validate_audit_time_range_rejects_1_year() {
    let result = validate_audit_time_range("2025-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "req-4");
    assert!(result.is_err());
}

#[test]
fn validate_audit_time_range_rejects_reversed_range() {
    let result = validate_audit_time_range("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z", "req-5");
    assert!(result.is_err());
}
