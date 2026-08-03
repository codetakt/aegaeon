// -----------------------------------------------------------------------
// S-FED-1: Federation list and resolve admission
// -----------------------------------------------------------------------

#[test]
fn federation_resolve_query_requires_standard_subject_and_trust_anchor() -> Result<(), String> {
    let valid = validate_federation_resolve_query(
        FederationResolveQuery {
            sub: vec!["https://rp.example".to_string()],
            trust_anchor: vec!["https://ta.example".to_string()],
            entity_type: vec!["openid_provider".to_string()],
            anchor: Vec::new(),
            unsupported: Vec::new(),
        },
        "https://op.example",
    )
    .map_err(|response| format!("valid resolve query rejected: {}", response.status()))?;
    assert_eq!(valid.sub, "https://rp.example");
    assert_eq!(valid.trust_anchors, vec!["https://ta.example".to_string()]);
    assert_eq!(valid.entity_types, vec!["openid_provider".to_string()]);

    for (query, label) in [
        (
            FederationResolveQuery {
                sub: Vec::new(),
                trust_anchor: vec!["https://ta.example".to_string()],
                entity_type: Vec::new(),
                anchor: Vec::new(),
                unsupported: Vec::new(),
            },
            "missing sub",
        ),
        (
            FederationResolveQuery {
                sub: vec!["https://rp.example".to_string()],
                trust_anchor: Vec::new(),
                entity_type: Vec::new(),
                anchor: Vec::new(),
                unsupported: Vec::new(),
            },
            "missing trust_anchor",
        ),
        (
            FederationResolveQuery {
                sub: vec!["https://rp.example".to_string()],
                trust_anchor: vec!["http://ta.example".to_string()],
                entity_type: Vec::new(),
                anchor: Vec::new(),
                unsupported: Vec::new(),
            },
            "invalid trust_anchor",
        ),
        (
            FederationResolveQuery {
                sub: vec!["https://rp.example".to_string()],
                trust_anchor: vec!["https://ta.example".to_string()],
                entity_type: Vec::new(),
                anchor: vec!["https://ta.example".to_string()],
                unsupported: Vec::new(),
            },
            "legacy anchor parameter",
        ),
        (
            FederationResolveQuery {
                sub: vec!["https://rp.example".to_string()],
                trust_anchor: vec!["https://ta.example".to_string()],
                entity_type: vec!["".to_string()],
                anchor: Vec::new(),
                unsupported: Vec::new(),
            },
            "empty entity_type",
        ),
        (
            FederationResolveQuery {
                sub: vec![
                    "https://rp.example".to_string(),
                    "https://rp2.example".to_string(),
                ],
                trust_anchor: vec!["https://ta.example".to_string()],
                entity_type: Vec::new(),
                anchor: Vec::new(),
                unsupported: Vec::new(),
            },
            "duplicate sub",
        ),
    ] {
        let response = validate_federation_resolve_query(query, "https://op.example")
            .err()
            .ok_or_else(|| format!("{label} must be rejected"))?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{label}");
    }

    Ok(())
}

#[test]
fn federation_resolve_query_parses_standard_query_string() -> TestResult {
    let parsed = FederationResolveQuery::from_raw_query(Some(
        "sub=https%3A%2F%2Frp.example&trust_anchor=https%3A%2F%2Fta.example&entity_type=openid_provider",
    ), "https://op.example")
    .map_err(|response| format!("resolve query parse rejected: {}", response.status()))?;

    assert_eq!(parsed.sub, vec!["https://rp.example".to_string()]);
    assert_eq!(parsed.trust_anchor, vec!["https://ta.example".to_string()]);
    assert_eq!(parsed.entity_type, vec!["openid_provider".to_string()]);
    assert!(parsed.anchor.is_empty());

    let parsed = FederationResolveQuery::from_raw_query(Some(
        "sub=https%3A%2F%2Frp.example&trust_anchor=https%3A%2F%2Fta-a.example&trust_anchor=https%3A%2F%2Fta-b.example&entity_type=openid_provider&entity_type=federation_entity",
    ), "https://op.example")
    .map_err(|response| format!("multi-value query parse rejected: {}", response.status()))?;
    let valid = validate_federation_resolve_query(parsed, "https://op.example")
        .map_err(|response| format!("multi-value query rejected: {}", response.status()))?;
    assert_eq!(
        valid.trust_anchors,
        vec![
            "https://ta-a.example".to_string(),
            "https://ta-b.example".to_string()
        ]
    );
    assert_eq!(
        valid.entity_types,
        vec![
            "openid_provider".to_string(),
            "federation_entity".to_string()
        ]
    );
    Ok(())
}

#[test]
fn federation_list_query_accepts_bounded_pagination() -> TestResult {
    let cursor = super::openid_federation::federation_list_cursor_for_tests("https://rp.example");
    let raw_query = format!("cursor={cursor}&limit=2");
    let pagination = super::openid_federation::federation_list_pagination_for_tests(
        Some(&raw_query),
        "https://op.example",
    )
    .map_err(|response| format!("list pagination rejected: {}", response.status()))?;

    assert_eq!(pagination, (Some("https://rp.example".to_string()), 2));
    Ok(())
}

#[test]
fn federation_resolve_query_rejects_unknown_parameters() -> TestResult {
    let parsed = FederationResolveQuery::from_raw_query(Some(
        "sub=https%3A%2F%2Frp.example&trust_anchor=https%3A%2F%2Fta.example&unexpected=1",
    ), "https://op.example")
    .map_err(|response| format!("unknown query parse rejected early: {}", response.status()))?;
    let response = validate_federation_resolve_query(parsed, "https://op.example")
        .err()
        .ok_or_else(|| "unknown resolve query parameter must be rejected".to_string())?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[test]
fn federation_resolve_query_rejects_bounded_parser_inputs() -> TestResult {
    let too_many_trust_anchors = std::iter::once("sub=https%3A%2F%2Frp.example".to_string())
        .chain((0..9).map(|idx| format!("trust_anchor=https%3A%2F%2Fta-{idx}.example")))
        .collect::<Vec<_>>()
        .join("&");
    let too_many_params = (0..33)
        .map(|idx| format!("unexpected{idx}=1"))
        .collect::<Vec<_>>()
        .join("&");
    let large_entity_type = format!(
        "sub=https%3A%2F%2Frp.example&trust_anchor=https%3A%2F%2Fta.example&entity_type={}",
        "a".repeat(129)
    );
    let large_query = format!("sub={}", "a".repeat(8 * 1024 + 1));

    for (raw_query, label) in [
        (too_many_trust_anchors.as_str(), "too many trust anchors"),
        (too_many_params.as_str(), "too many query parameters"),
        (large_entity_type.as_str(), "large entity type"),
        (large_query.as_str(), "large raw query"),
    ] {
        let response = FederationResolveQuery::from_raw_query(Some(raw_query), "https://op.example")
            .err()
            .ok_or_else(|| format!("{label} must be rejected"))?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{label}");
    }
    Ok(())
}
