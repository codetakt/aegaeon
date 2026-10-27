use crate::federation::trust_chain::verify_signed_path;

fn names(permitted: Option<&[&str]>, excluded: Option<&[&str]>) -> NamingConstraints {
    NamingConstraints {
        permitted: permitted.map(|v| v.iter().map(|s| (*s).to_owned()).collect()),
        excluded: excluded.map(|v| v.iter().map(|s| (*s).to_owned()).collect()),
    }
}

fn constrain(f: &mut SignedPathFixture, index: usize, naming: NamingConstraints) {
    f.subordinates[index]
        .constraints
        .get_or_insert_with(Constraints::default)
        .naming_constraints = Some(naming);
}

fn rename(f: &mut SignedPathFixture, index: usize, id: &str) {
    f.configs[index].iss = id.into();
    f.configs[index].sub = id.into();
    if index < f.subordinates.len() {
        f.subordinates[index].sub = id.into();
    } else {
        f.anchor.entity_id = id.into();
    }
    if index > 0 {
        f.subordinates[index - 1].iss = id.into();
        f.configs[index - 1].authority_hints = Some(vec![id.into()]);
    }
}

fn verified(f: &SignedPathFixture) -> Result<TrustChain, FederationError> {
    verify_signed_path(&f.jwts(), &f.configs[0].iss, &f.anchor, NOW)
}

#[test]
fn naming_host_boundary_normalization_and_signed_identity_preservation() {
    let _guard = raw_json_env_guard();
    for (constraint, id, allowed) in [
        ("host.example.com", "https://host.example.com/path", true),
        (
            "host.example.com",
            "https://host.example.com:8443/other",
            true,
        ),
        ("host.example.com", "https://a.host.example.com", false),
        (".example.com", "https://example.com", false),
        (".example.com", "https://host.example.com", true),
        (".example.com", "https://a.host.example.com", true),
        (".example.com", "https://badexample.com", false),
        (
            ".example.com",
            "https://example.com.attacker.example",
            false,
        ),
        (".EXAMPLE.COM.", "HTTPS://Host.Example.COM.:8443/path", true),
        ("xn--bcher-kva.example", "https://bücher.example", true),
        ("localhost.", "https://LOCALHOST", true),
        ("host.example.com", "https://%68ost.example.com", true),
        (
            "host.example.com",
            "https://other.example/host.example.com",
            false,
        ),
    ] {
        let mut f = SignedPathFixture::new(0);
        rename(&mut f, 0, id);
        constrain(&mut f, 0, names(Some(&[constraint]), None));
        let result = verified(&f);
        assert_eq!(result.is_ok(), allowed, "{constraint} versus {id}");
        assert_eq!(
            f.detached().trust_chain.resolved_metadata().is_ok(),
            allowed
        );
        if let Ok(chain) = result {
            assert_eq!(chain.chain[0].iss, id);
            assert_eq!(chain.chain[1].sub, id);
            assert_eq!(
                must_ok(serde_json::to_value(&chain.chain)),
                must_ok(serde_json::to_value(&f.detached().trust_chain.chain))
            );
        }
    }
}

#[test]
fn naming_empty_forms_and_effective_ip_constraints() {
    let _guard = raw_json_env_guard();
    for id in [
        "https://localhost",
        "https://127.0.0.1",
        "https://127.1",
        "https://[::1]",
        "https://host.example",
    ] {
        let mut f = SignedPathFixture::new(0);
        rename(&mut f, 0, id);
        must_ok(verified(&f));
        for neutral in [names(None, None), names(None, Some(&[]))] {
            constrain(&mut f, 0, neutral);
            must_ok(verified(&f));
        }
        constrain(&mut f, 0, names(Some(&[]), None));
        assert!(verified(&f).is_err());
        constrain(&mut f, 0, names(None, Some(&["unrelated.example"])));
        assert_eq!(
            verified(&f).is_ok(),
            id == "https://localhost" || id == "https://host.example"
        );
    }
}

#[test]
fn naming_all_descendants_ancestor_intersection_and_issuer_exemption() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for intermediates in [0, 2] {
            let mut f = SignedPathFixture::new(intermediates);
            // Issuer/anchor is outside every restricted subordinate namespace.
            rename(&mut f, intermediates + 1, "https://anchor.other.example");
            for index in 0..=intermediates {
                constrain(&mut f, index, names(Some(&[".example.com"]), None));
            }
            constrain(
                &mut f,
                0,
                names(Some(&["unrelated.example", "entity-0.example.com"]), None),
            );
            must_ok(verified(&f));
            let resolved = must_ok(
                resolve_trust_chain_with_jwts(
                    &f.configs[0].iss,
                    &[f.anchor.clone()],
                    &f.fetcher(),
                    NOW,
                )
                .await,
            );
            assert_eq!(
                must_ok(serde_json::to_value(&resolved.trust_chain.chain)),
                must_ok(serde_json::to_value(&f.detached().trust_chain.chain))
            );
            constrain(
                &mut f,
                intermediates,
                names(Some(&[".example.com"]), Some(&["entity-0.example.com"])),
            );
            assert!(verified(&f).is_err());
            assert!(resolve_trust_chain_with_jwts(
                &f.configs[0].iss,
                &[f.anchor.clone()],
                &f.fetcher(),
                NOW
            )
            .await
            .is_err());
            constrain(
                &mut f,
                intermediates,
                names(Some(&[".different.example"]), None),
            );
            assert!(verified(&f).is_err());
        }
        let mut f = SignedPathFixture::new(2);
        rename(&mut f, 0, "https://leaf.dept.example.com");
        rename(&mut f, 1, "https://intermediate.dept.example.com");
        constrain(&mut f, 0, names(Some(&["leaf.dept.example.com"]), None));
        constrain(&mut f, 1, names(Some(&[".dept.example.com"]), None));
        constrain(&mut f, 2, names(Some(&[".example.com"]), None));
        must_ok(verified(&f)); // nonidentical overlapping subtrees, lower constraints exclude own issuer
        rename(&mut f, 1, "https://intermediate.other.example");
        assert!(verified(&f).is_err()); // leaf still valid; upper constraint rejects intermediate
        assert!(f.detached().trust_chain.resolved_metadata().is_err());
    });
}

#[test]
fn naming_rejects_before_metadata_shortcuts_and_preserves_other_constraints() {
    let _guard = raw_json_env_guard();
    let mut f = SignedPathFixture::new(1);
    for metadata in [None, Some(HashMap::new()), f.configs[0].metadata.clone()] {
        f.configs[0].metadata = metadata;
        constrain(&mut f, 1, names(Some(&[]), None));
        f.subordinates[1]
            .constraints
            .as_mut()
            .unwrap()
            .allowed_entity_types = Some(vec![]);
        assert!(verified(&f).is_err());
        assert!(f.detached().trust_chain.resolved_metadata().is_err());
    }
    constrain(&mut f, 1, names(None, None));
    must_ok(verified(&f));
    f.subordinates[1]
        .constraints
        .as_mut()
        .unwrap()
        .max_path_length = Some(0);
    assert!(verified(&f).is_err());
    f.subordinates[1]
        .constraints
        .as_mut()
        .unwrap()
        .max_path_length = None;
    f.subordinates[1]
        .constraints
        .as_mut()
        .unwrap()
        .allowed_leaf_entity_types = Some(vec![]);
    assert!(verified(&f).is_err());
    f.subordinates[1]
        .constraints
        .as_mut()
        .unwrap()
        .allowed_leaf_entity_types = None;
    f.subordinates[1].metadata_policy_crit = Some(vec!["unsupported".into()]);
    assert!(verified(&f).is_err());
    f.subordinates[1].metadata_policy_crit = None;
    for index in [0, 2, 4] {
        let mut chain = f.detached().trust_chain;
        chain.chain[index].constraints = Some(Constraints {
            naming_constraints: Some(names(None, None)),
            ..Constraints::default()
        });
        assert!(chain.resolved_metadata().is_err());
    }
    constrain(&mut f, 0, names(Some(&["bad..example"]), None));
    assert!(f.detached().trust_chain.resolved_metadata().is_err());
}

mod cache {
    use super::*;
    include!("naming_constraints_cache.rs");
}
