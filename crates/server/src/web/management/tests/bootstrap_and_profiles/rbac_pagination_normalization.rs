
// ---------------------------------------------------------------
// P1: RBAC role helpers
// ---------------------------------------------------------------

#[test]
fn role_allows_manage_lifecycle_for_owner() {
    assert!(role_allows_manage_lifecycle("OWNER"));
}

#[test]
fn role_allows_manage_lifecycle_for_administrator() {
    assert!(role_allows_manage_lifecycle("ADMINISTRATOR"));
}

#[test]
fn role_denies_manage_lifecycle_for_member() {
    assert!(!role_allows_manage_lifecycle("MEMBER"));
}

#[test]
fn role_denies_manage_lifecycle_for_viewer() {
    assert!(!role_allows_manage_lifecycle("VIEWER"));
}

#[test]
fn role_denies_manage_lifecycle_for_empty() {
    assert!(!role_allows_manage_lifecycle(""));
}

#[test]
fn role_denies_manage_lifecycle_for_lowercase() {
    assert!(!role_allows_manage_lifecycle("owner"));
    assert!(!role_allows_manage_lifecycle("administrator"));
}

// ---------------------------------------------------------------
// P1: parse_uuid_param
// ---------------------------------------------------------------

#[test]
fn parse_uuid_param_accepts_valid_uuid() -> TestResult {
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let Ok(result) = parse_uuid_param(uuid, "teamId", "req-1") else {
        return Err(io::Error::other("expected UUID to parse").into());
    };
    assert_eq!(result.to_string(), uuid);
    Ok(())
}

#[test]
fn parse_uuid_param_rejects_invalid_uuid() {
    let result = parse_uuid_param("not-a-uuid", "teamId", "req-1");
    assert!(result.is_err());
}

#[test]
fn parse_uuid_param_rejects_empty_string() {
    let result = parse_uuid_param("", "teamId", "req-1");
    assert!(result.is_err());
}

#[tokio::test]
async fn parse_uuid_param_error_details_do_not_echo_input_value() -> TestResult {
    let invalid_uuid = "not-a-uuid-with-attacker-controlled-content";
    let response = must_err!(
        parse_uuid_param(invalid_uuid, "teamId", "req-1"),
        "invalid UUID must be rejected",
    );
    let body = management_error_response_body(response).await?;
    assert_eq!(
        body.details.as_ref(),
        Some(&serde_json::json!({ "field": "teamId" }))
    );
    let serialized = serde_json::to_string(&body)?;
    assert!(!serialized.contains(invalid_uuid));
    assert!(!serialized.contains("attacker-controlled-content"));
    Ok(())
}

// ---------------------------------------------------------------
// P1: Pagination helpers
// ---------------------------------------------------------------

#[test]
fn pagination_params_defaults() -> TestResult {
    let query = PaginationQuery {
        page_size: None,
        page_token: None,
    };
    let pagination = must_ok!(pagination_params(&query, 2, "req-1"), "valid pagination");
    assert_eq!(pagination.limit, i64::from(DEFAULT_PAGE_SIZE));
    assert_eq!(pagination.cursor_value(0), None);
    Ok(())
}

#[test]
fn pagination_params_custom_size() -> TestResult {
    let query = PaginationQuery {
        page_size: Some(10),
        page_token: None,
    };
    let pagination = must_ok!(pagination_params(&query, 2, "req-1"), "valid pagination");
    assert_eq!(pagination.limit, 10);
    assert_eq!(pagination.cursor_value(0), None);
    Ok(())
}

#[test]
fn pagination_params_clamps_above_max() -> TestResult {
    let query = PaginationQuery {
        page_size: Some(999),
        page_token: None,
    };
    let pagination = must_ok!(pagination_params(&query, 2, "req-1"), "valid pagination");
    assert_eq!(pagination.limit, i64::from(MAX_PAGE_SIZE));
    Ok(())
}

#[test]
fn pagination_params_clamps_zero_to_one() -> TestResult {
    let query = PaginationQuery {
        page_size: Some(0),
        page_token: None,
    };
    let pagination = must_ok!(pagination_params(&query, 2, "req-1"), "valid pagination");
    assert_eq!(pagination.limit, 1);
    Ok(())
}

#[test]
fn pagination_params_with_valid_page_token() -> TestResult {
    let token = encode_keyset_page_token([
        "2026-07-04T01:02:03.123456Z".to_string(),
        "018f3b8f-0c27-7d93-aef1-5af7d75a2de1".to_string(),
    ]);
    let query = PaginationQuery {
        page_size: Some(25),
        page_token: Some(token),
    };
    let pagination = must_ok!(pagination_params(&query, 2, "req-1"), "valid pagination");
    assert_eq!(pagination.limit, 25);
    assert_eq!(
        pagination.cursor_value(0),
        Some("2026-07-04T01:02:03.123456Z")
    );
    assert_eq!(
        pagination.cursor_value(1),
        Some("018f3b8f-0c27-7d93-aef1-5af7d75a2de1")
    );
    Ok(())
}

#[test]
fn pagination_params_rejects_invalid_page_token() -> TestResult {
    let query = PaginationQuery {
        page_size: Some(25),
        page_token: Some("garbage".to_string()),
    };
    let err = must_err!(
        pagination_params(&query, 2, "req-1"),
        "invalid pageToken must fail closed"
    );
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

// ---------------------------------------------------------------
// P1: Normalization helpers
// ---------------------------------------------------------------

#[test]
fn normalize_lower_list_trims_lowercases_dedupes() {
    let input = vec![
        " HELLO ".to_string(),
        "world".to_string(),
        "HELLO".to_string(),
        String::new(),
    ];
    let result = normalize_lower_list(&input);
    assert_eq!(result, vec!["hello", "world"]);
}

#[test]
fn normalize_lower_list_empty_input() {
    let result = normalize_lower_list(&[]);
    assert!(result.is_empty());
}

#[test]
fn normalize_lower_list_all_empty_strings() {
    let input = vec![String::new(), "  ".to_string()];
    let result = normalize_lower_list(&input);
    assert!(result.is_empty());
}
