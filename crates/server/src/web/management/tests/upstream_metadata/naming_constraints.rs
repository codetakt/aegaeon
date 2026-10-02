use super::*;
use crate::web::upstream_authorize::discovery::fetch_upstream_authorize_discovery_with;

#[test]
fn federation_naming_refuses_upstream_operations_before_credentials() -> ManagementTestResult {
    run(async {
        for intermediates in [0, 2] {
            let f = Fixture::new(intermediates).await?;
            let mut valid = f.chain(f.metadata(), &[], None);
            f.set_naming_constraints(&mut valid, intermediates, &[".example"]);
            f.configure(&valid).await?;
            let context = f.authorize_context();
            let input = authorize_input(&["openid"], Some("high"));
            fetch_upstream_authorize_discovery_with(
                &f.state,
                "https://local.example",
                &context,
                &input,
                |_, _| std::future::ready(Ok(valid.clone())),
            )
            .await
            .map_err(response_error)?;
            assert_eq!(f.calls.load(Ordering::SeqCst), 0);
            perform_upstream_callback_exchange_with(
                &f.state,
                &f.request,
                "code",
                "https://local.example",
                fail_acquisition,
            )
            .await
            .map_err(response_error)?;
            assert_eq!(f.calls.load(Ordering::SeqCst), 1);
            let mut invalid = valid.clone();
            // With intermediates, the leaf still matches but an intermediate does not.
            f.set_naming_constraints(
                &mut invalid,
                intermediates,
                if intermediates == 0 {
                    &["other.example"]
                } else {
                    &["upstream.example"]
                },
            );
            cache(&f.state, &invalid).await?;
            f.reset_discovery()?;
            assert!(fetch_upstream_authorize_discovery_with(
                &f.state,
                "https://local.example",
                &context,
                &input,
                |_, _| std::future::ready(Ok(invalid.clone())),
            )
            .await
            .is_err());
            f.reset_discovery()?;
            assert!(perform_upstream_callback_exchange_with(
                &f.state,
                &f.request,
                "code",
                "https://local.example",
                |_, _| std::future::ready(Ok(invalid.clone())),
            )
            .await
            .is_err());
            f.reset_discovery()?;
            assert!(perform_upstream_refresh_exchange_with(
                &f.state,
                "https://local.example",
                &f.refresh_link(),
                &f.profile,
                |_, _| std::future::ready(Ok(invalid.clone())),
            )
            .await
            .is_err());
            assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        }
        Ok(())
    })
}

#[test]
fn federation_naming_management_refresh_admits_only_valid_raw_payload() -> ManagementTestResult {
    use crate::management::types::FederationTrustChainEntry;
    use crate::web::management::federation_cache::resolve_refreshed_trust_chain_payload;
    run(async {
        let f = Fixture::new(2).await?;
        let mut valid = f.chain(f.metadata(), &[], None);
        f.set_naming_constraints(&mut valid, 2, &[".example"]);
        let anchor = valid.trust_chain.anchor.clone();
        let existing = FederationTrustChainEntry {
            id: Uuid::new_v4().to_string(),
            environment_id: Uuid::new_v4().to_string(),
            leaf_entity_id: ISSUER.into(),
            anchor_entity_id: anchor.entity_id.clone(),
            chain_jwts: json!(["retained old evidence"]),
            resolved_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-01-01T00:01:00Z".into(),
        };
        let payload = resolve_refreshed_trust_chain_payload(
            &existing,
            vec![anchor.clone()],
            "valid-naming",
            |_, _, _| std::future::ready(Ok(valid.chain_jwts.clone())),
        )
        .await
        .map_err(response_error)?;
        assert_eq!(payload, json!(valid.chain_jwts));
        f.set_naming_constraints(&mut valid, 2, &["upstream.example"]);
        let refused = resolve_refreshed_trust_chain_payload(
            &existing,
            vec![anchor],
            "invalid-naming",
            |_, _, _| std::future::ready(Ok(valid.chain_jwts.clone())),
        )
        .await;
        assert!(refused.is_err()); // No storable payload returned; no database/router execution.
        assert_eq!(existing.chain_jwts, json!(["retained old evidence"]));
        Ok(())
    })
}
