// ── Trust Chain Resolution ───────────────────────────────────────

fn resolve_trust_chain_for_test(
    leaf_entity_id: &str,
    trust_anchors: &[TrustAnchor],
    fetcher: &dyn FederationFetcher,
    now: i64,
) -> Result<TrustChain, FederationError> {
    block_on_test_future(crate::federation::resolve_trust_chain(
        leaf_entity_id,
        trust_anchors,
        fetcher,
        now,
    ))
}

#[test]
fn resolve_trust_chain_direct() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: Some(json!({})),
    }];

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(
        ta_id,
        leaf_id,
        sample_subordinate_statement(ta_id, leaf_id, now),
    );

    let chain = must_ok(resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now));
    assert_eq!(must_ok(chain.depth()), 1);
    assert_eq!(must_ok(chain.leaf()).iss, leaf_id);
    assert_eq!(must_ok(chain.trust_anchor_config()).iss, ta_id);
    assert_eq!(chain.chain.len(), 3); // leaf, sub_stmt, ta
}

#[test]
fn resolve_trust_chain_rejects_leaf_entity_configuration_mismatch() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![sample_trust_anchor(ta_id)];
    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(
        leaf_id,
        sample_entity_config("https://other-rp.example.com", now),
    );

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);

    assert!(
        result.is_err(),
        "leaf entity configuration must match the requested leaf entity_id"
    );
}

#[test]
fn resolve_trust_chain_direct_rejects_subordinate_subject_mismatch() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![sample_trust_anchor(ta_id)];
    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(
        ta_id,
        leaf_id,
        sample_subordinate_statement(ta_id, "https://other-rp.example.com", now),
    );

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);

    assert!(
        result.is_err(),
        "direct subordinate statement subject must match the current entity"
    );
}

#[test]
fn resolve_trust_chain_direct_rejects_subordinate_issuer_mismatch() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![sample_trust_anchor(ta_id)];
    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(
        ta_id,
        leaf_id,
        sample_subordinate_statement("https://evil.example.com", leaf_id, now),
    );

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);

    assert!(
        result.is_err(),
        "direct subordinate statement issuer must match the superior entity"
    );
}

#[test]
fn resolve_trust_chain_direct_rejects_trust_anchor_config_mismatch() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![sample_trust_anchor(ta_id)];
    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config("https://evil.example.com", now));
    fetcher.add_subordinate_stmt(
        ta_id,
        leaf_id,
        sample_subordinate_statement(ta_id, leaf_id, now),
    );

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);

    assert!(
        result.is_err(),
        "trust anchor entity configuration must match the configured anchor"
    );
}

#[test]
fn resolve_trust_chain_intermediate() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let int_id = "https://intermediate.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: Some(json!({})),
    }];

    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.authority_hints = Some(vec![int_id.to_string()]);

    let mut int_config = sample_entity_config(int_id, now);
    int_config.authority_hints = Some(vec![ta_id.to_string()]);

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
        int_id,
        sample_subordinate_statement(ta_id, int_id, now),
    );

    let chain = must_ok(resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now));
    assert_eq!(must_ok(chain.depth()), 2);
    assert_eq!(chain.chain.len(), 5); // leaf, sub1, int, sub2, ta
    assert_eq!(must_ok(chain.leaf()).iss, leaf_id);
    assert_eq!(must_ok(chain.trust_anchor_config()).iss, ta_id);
    // Intermediate is at index 2
    assert_eq!(chain.chain[2].iss, int_id);
}

struct RevisitedEntityGuardFetcher {
    inner: MockFetcher,
    guarded_entity_id: &'static str,
    fetch_count: std::sync::atomic::AtomicUsize,
}

impl FederationFetcher for RevisitedEntityGuardFetcher {
    fn fetch_entity_configuration<'a>(
        &'a self,
        entity_id: &'a str,
    ) -> FederationFetchFuture<'a, EntityStatement> {
        Box::pin(async move {
            if entity_id == self.guarded_entity_id {
                let fetch_count = self
                    .fetch_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    .saturating_add(1);
                assert_eq!(
                    fetch_count, 1,
                    "trust-chain cycle detection must reject revisiting {entity_id} before refetch"
                );
            }
            self.inner.fetch_entity_configuration(entity_id).await
        })
    }

    fn fetch_subordinate_statement<'a>(
        &'a self,
        authority_entity_id: &'a str,
        authority_config: &'a EntityStatement,
        subordinate_entity_id: &'a str,
        issuer_jwks: &'a JwkSet,
    ) -> FederationFetchFuture<'a, EntityStatement> {
        Box::pin(async move {
            self.inner
                .fetch_subordinate_statement(
                    authority_entity_id,
                    authority_config,
                    subordinate_entity_id,
                    issuer_jwks,
                )
                .await
        })
    }
}

#[test]
fn resolve_trust_chain_rejects_cyclic_authority_hints_before_refetch() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let int_id = "https://intermediate.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![sample_trust_anchor(ta_id)];

    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.authority_hints = Some(vec![int_id.to_string()]);
    let mut int_config = sample_entity_config(int_id, now);
    int_config.authority_hints = Some(vec![leaf_id.to_string()]);

    let mut inner = MockFetcher::new();
    inner.add_entity_config(leaf_id, leaf_config);
    inner.add_entity_config(int_id, int_config);
    inner.add_subordinate_stmt(
        int_id,
        leaf_id,
        sample_subordinate_statement(int_id, leaf_id, now),
    );
    let fetcher = RevisitedEntityGuardFetcher {
        inner,
        guarded_entity_id: leaf_id,
        fetch_count: std::sync::atomic::AtomicUsize::new(0),
    };

    let err = must_err(resolve_trust_chain_for_test(
        leaf_id,
        &trust_anchors,
        &fetcher,
        now,
    ));

    assert!(matches!(err, FederationError::ChainResolution(_)));
    assert_eq!(
        fetcher
            .fetch_count
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "cyclic authority_hints must not refetch the leaf entity configuration"
    );
}

#[test]
fn resolve_trust_chain_intermediate_rejects_authority_config_mismatch() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let int_id = "https://intermediate.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![sample_trust_anchor(ta_id)];
    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.authority_hints = Some(vec![int_id.to_string()]);

    let mut wrong_int_config = sample_entity_config("https://evil.example.com", now);
    wrong_int_config.authority_hints = Some(vec![ta_id.to_string()]);

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, leaf_config);
    fetcher.add_entity_config(int_id, wrong_int_config);

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);

    assert!(
        result.is_err(),
        "intermediate entity configuration must match the authority hint"
    );
}

#[test]
fn resolve_trust_chain_intermediate_rejects_subordinate_subject_mismatch() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let int_id = "https://intermediate.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![sample_trust_anchor(ta_id)];
    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.authority_hints = Some(vec![int_id.to_string()]);
    let mut int_config = sample_entity_config(int_id, now);
    int_config.authority_hints = Some(vec![ta_id.to_string()]);

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, leaf_config);
    fetcher.add_entity_config(int_id, int_config);
    fetcher.add_subordinate_stmt(
        int_id,
        leaf_id,
        sample_subordinate_statement(int_id, "https://other-rp.example.com", now),
    );

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);

    assert!(
        result.is_err(),
        "intermediate subordinate statement subject must match the current entity"
    );
}

#[test]
fn resolve_trust_chain_intermediate_rejects_subordinate_issuer_mismatch() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let int_id = "https://intermediate.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![sample_trust_anchor(ta_id)];
    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.authority_hints = Some(vec![int_id.to_string()]);
    let mut int_config = sample_entity_config(int_id, now);
    int_config.authority_hints = Some(vec![ta_id.to_string()]);

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, leaf_config);
    fetcher.add_entity_config(int_id, int_config);
    fetcher.add_subordinate_stmt(
        int_id,
        leaf_id,
        sample_subordinate_statement("https://evil.example.com", leaf_id, now),
    );

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);

    assert!(
        result.is_err(),
        "intermediate subordinate statement issuer must match the superior entity"
    );
}

#[test]
fn resolve_trust_chain_no_path() {
    let now = 1_700_000_000_i64;
    let leaf_id = "https://rp.example.com";
    let unknown_ta = "https://unknown-ta.example.com";

    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.authority_hints = Some(vec![unknown_ta.to_string()]);

    let trust_anchors = vec![TrustAnchor {
        entity_id: "https://ta.example.com".to_string(),
        jwks: sample_jwks(),
        metadata_policy: None,
    }];

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, leaf_config);

    let err = must_err(resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now));
    assert!(matches!(err, FederationError::ChainResolution(_)));
}

#[test]
fn resolve_trust_chain_rejects_excessive_authority_hint_fanout() {
    let now = 1_700_000_000_i64;
    let leaf_id = "https://rp.example.com";

    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.authority_hints = Some(
        (0..17)
            .map(|idx| format!("https://ta-{idx}.example.com"))
            .collect(),
    );

    let trust_anchors = vec![sample_trust_anchor("https://ta.example.com")];
    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, leaf_config);

    let err = must_err(resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now));
    assert!(
        matches!(&err, FederationError::ChainResolution(message) if message.contains("too many authority_hints")),
        "unexpected error: {err}"
    );
}

#[test]
fn resolve_trust_chain_no_authority_hints() {
    let now = 1_700_000_000_i64;
    let leaf_id = "https://rp.example.com";

    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.authority_hints = None;

    let trust_anchors = vec![TrustAnchor {
        entity_id: "https://ta.example.com".to_string(),
        jwks: sample_jwks(),
        metadata_policy: None,
    }];

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, leaf_config);

    let err = must_err(resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now));
    assert!(matches!(
        err,
        FederationError::MissingField("authority_hints")
    ));
}

#[test]
fn resolve_trust_chain_expired_leaf() {
    let now = 1_700_000_000_i64;
    let leaf_id = "https://rp.example.com";

    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.exp = now - 200; // expired
    leaf_config.iat = now - 400;

    let trust_anchors = vec![TrustAnchor {
        entity_id: "https://ta.example.com".to_string(),
        jwks: sample_jwks(),
        metadata_policy: None,
    }];

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, leaf_config);

    let err = must_err(resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now));
    assert!(matches!(err, FederationError::Expired));
}

#[test]
fn trust_chain_empty_chain_fails_closed() {
    let chain = TrustChain {
        chain: Vec::new(),
        anchor: TrustAnchor {
            entity_id: "https://ta.example.com".to_string(),
            jwks: sample_jwks(),
            metadata_policy: None,
        },
    };

    assert!(matches!(
        chain.leaf(),
        Err(FederationError::Validation(message)) if message.contains("missing leaf entity")
    ));
    assert!(matches!(
        chain.trust_anchor_config(),
        Err(FederationError::Validation(message)) if message.contains("missing trust anchor")
    ));
    assert!(matches!(
        chain.depth(),
        Err(FederationError::Validation(message)) if message == "trust chain is empty"
    ));
    assert!(matches!(
        chain.resolved_metadata(),
        Err(FederationError::Validation(message)) if message.contains("missing leaf entity")
    ));
}
