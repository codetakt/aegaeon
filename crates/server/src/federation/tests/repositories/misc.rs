// ── host_matches_allowlist helper ──────────────────────────────

#[test]
fn host_matches_allowlist_exact() {
    let allowed = vec!["example.com".to_string()];
    assert!(host_matches_allowlist("example.com", &allowed));
    assert!(!host_matches_allowlist("evil.com", &allowed));
}

#[test]
fn host_matches_allowlist_subdomain() {
    let allowed = vec!["example.com".to_string()];
    assert!(host_matches_allowlist("sub.example.com", &allowed));
    assert!(host_matches_allowlist("deep.sub.example.com", &allowed));
    assert!(!host_matches_allowlist("notexample.com", &allowed));
}

#[test]
fn host_matches_allowlist_multiple() {
    let allowed = vec!["a.example.com".to_string(), "b.example.com".to_string()];
    assert!(host_matches_allowlist("a.example.com", &allowed));
    assert!(host_matches_allowlist("b.example.com", &allowed));
    assert!(!host_matches_allowlist("c.example.com", &allowed));
}

// ── P8-TA-1: resolve_chain_up logging/timeout ───────────────────

#[test]
fn resolve_chain_up_logs_and_reports_errors() {
    // When all authority_hints fail, the error message should reference
    // the current entity. We can't directly test tracing output, but
    // we verify the correct error variant is returned with context.
    let now = 1_700_000_000_i64;
    let leaf_id = "https://rp.example.com";
    let unknown_hint = "https://unknown.example.com";

    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.authority_hints = Some(vec![unknown_hint.to_string()]);

    let trust_anchors = vec![TrustAnchor {
        entity_id: "https://ta.example.com".to_string(),
        jwks: sample_jwks(),
        metadata_policy: None,
    }];

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, leaf_config);

    let err = must_err(block_on_test_future(resolve_trust_chain(
        leaf_id,
        &trust_anchors,
        &fetcher,
        now,
    )));
    if let FederationError::ChainResolution(msg) = err {
        assert!(
            msg.contains(leaf_id),
            "error should mention leaf entity: {msg}"
        );
    } else {
        assert!(
            matches!(&err, FederationError::ChainResolution(_)),
            "expected ChainResolution, got: {err}"
        );
    }
}

#[test]
fn resolve_chain_up_intermediate_no_hints_continues() {
    // An intermediate authority with no authority_hints should be
    // gracefully skipped (with logging) rather than panic.
    let now = 1_700_000_000_i64;
    let leaf_id = "https://rp.example.com";
    let int_id = "https://int.example.com";
    let ta_id = "https://ta.example.com";

    let mut leaf_config = sample_entity_config(leaf_id, now);
    // First hint is an intermediate with no hints, second is the actual TA
    leaf_config.authority_hints = Some(vec![int_id.to_string(), ta_id.to_string()]);

    // int has no authority_hints — should be skipped
    let mut int_config = sample_entity_config(int_id, now);
    int_config.authority_hints = None;

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: Some(json!({})),
    }];

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, leaf_config);
    fetcher.add_entity_config(int_id, int_config);
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(
        int_id,
        leaf_id,
        sample_subordinate_statement(int_id, leaf_id, now),
    );
    fetcher.add_subordinate_stmt(
        ta_id,
        leaf_id,
        sample_subordinate_statement(ta_id, leaf_id, now),
    );

    // Should succeed via the TA hint even though int has no hints
    let chain = must_ok(block_on_test_future(resolve_trust_chain(
        leaf_id,
        &trust_anchors,
        &fetcher,
        now,
    )));
    assert_eq!(chain.anchor.entity_id, ta_id);
}
