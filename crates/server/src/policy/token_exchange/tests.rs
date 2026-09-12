use super::*;

#[test]
fn capture_requires_a_trusted_client_scope_ceiling() {
    let p = policy();
    let source = vec!["read".into(), "write".into()];
    assert!(p
        .capture("issuer", "client", "user", "userinfo", &source, &[])
        .is_none());
    let grant = p
        .capture(
            "issuer",
            "client",
            "user",
            "userinfo",
            &source,
            &["api.read".into()],
        )
        .expect("permitted read capability");
    assert!(p
        .authorize(&grant, "issuer", "client", "user", "userinfo", &source, "api", None)
        .is_ok());
    assert!(matches!(
        p.authorize(
            &grant,
            "issuer",
            "client",
            "user",
            "userinfo",
            &source,
            "api",
            Some(&["api.write".into()])
        ),
        Err(ExchangeAuthorizationError::InvalidScope(_))
    ));
}

#[test]
fn older_grant_without_client_scope_ceiling_is_never_upgraded() {
    let p = policy();
    let source = vec!["read".into()];
    let grant = p
        .capture(
            "issuer",
            "client",
            "user",
            "userinfo",
            &source,
            &["api.read".into()],
        )
        .expect("captured ceiling");
    let mut encoded = serde_json::to_value(&grant).expect("serialize");
    encoded["version"] = serde_json::json!(1);
    let old: ExchangeGrant =
        serde_json::from_value(encoded).expect("historical record is readable");
    assert!(matches!(
        p.authorize(&old, "issuer", "client", "user", "userinfo", &source, "api", None),
        Err(ExchangeAuthorizationError::InvalidTarget(_))
    ));
    assert!(!old.is_restriction_of(&old));
    assert!(!old.covers_output("client", "user", "api", &["api.read".into()]));
    assert!(!old.attenuate(&source).has_client_scope_ceiling());
}

fn policy() -> TokenExchangePolicy {
    serde_json::from_value(serde_json::json!({
        "version":1,
        "targets":[{"audience":"api", "resourceAliases":["https://api.example/resource?q=1"]}],
        "rules":[
            {"clientId":"client","sourceAudience":"userinfo","targetAudience":"api",
             "scopes":[{"targetScope":"api.read","sourceScopes":["read"]},
                       {"targetScope":"api.write","sourceScopes":["write"]}],
             "defaultScopes":["api.read"]},
            {"clientId":"client","sourceAudience":"api","targetAudience":"api",
             "scopes":[{"targetScope":"api.read","sourceScopes":["api.read"]},
                       {"targetScope":"api.write","sourceScopes":["api.write"]}],
             "defaultScopes":["api.read"]}]
    }))
    .expect("policy fixture")
}

#[test]
fn exchange_requires_all_source_conditions_and_authorized_defaults() {
    let mut p = policy();
    p.rules[0].scopes[1].source_scopes = vec!["read".into(), "write".into()];
    assert!(p
        .capture(
            "issuer",
            "client",
            "user",
            "userinfo",
            &["write".into()],
            &["api.read".into(), "api.write".into()]
        )
        .is_none());
    for defaults in [vec![], vec!["api.read".into(), "api.write".into()]] {
        p.rules[0].default_scopes = defaults;
        p.validate().expect("valid conditional defaults");
        let actual = vec!["read".into()];
        let grant = p
            .capture(
                "issuer",
                "client",
                "user",
                "userinfo",
                &actual,
                &["api.read".into(), "api.write".into()],
            )
            .expect("read capability");
        assert!(p
            .authorize(&grant, "issuer", "client", "user", "userinfo", &actual, "api", None)
            .is_err());
        assert!(p
            .authorize(
                &grant,
                "issuer",
                "client",
                "user",
                "userinfo",
                &actual,
                "api",
                Some(&["api.read".into()])
            )
            .is_ok());
    }
}

#[test]
fn exchange_selected_target_cannot_recover_another_original_target() {
    let mut p = policy();
    p.targets.push(ExchangeTarget {
        audience: "other".into(),
        resource_aliases: vec![],
    });
    for source in ["userinfo", "api"] {
        let mut rule = p.rules[usize::from(source == "api")].clone();
        rule.target_audience = "other".into();
        p.rules.push(rule);
    }
    p.validate().expect("two allowed targets");
    let source_scope = vec!["read".into()];
    let grant = p
        .capture(
            "issuer",
            "client",
            "user",
            "userinfo",
            &source_scope,
            &["api.read".into(), "api.write".into()],
        )
        .expect("both targets captured");
    assert!(p
        .authorize(
            &grant,
            "issuer",
            "client",
            "user",
            "userinfo",
            &source_scope,
            "other",
            None
        )
        .is_ok());
    let (scope, narrowed) = p
        .authorize(
            &grant,
            "issuer",
            "client",
            "user",
            "userinfo",
            &source_scope,
            "api",
            None,
        )
        .expect("choose api");
    assert!(p
        .authorize(&narrowed, "issuer", "client", "user", "api", &scope, "other", None)
        .is_err());
    assert!(p
        .authorize(&narrowed, "issuer", "client", "user", "api", &scope, "api", None)
        .is_ok());
}

#[test]
fn explicit_target_authority_cannot_regrow_after_refresh_or_exchange() {
    let p = policy();
    p.validate().expect("valid policy");
    let root = p
        .capture(
            "issuer",
            "client",
            "user",
            "userinfo",
            &["read".into(), "write".into()],
            &["api.read".into(), "api.write".into()],
        )
        .expect("authority");
    let actual = vec!["read".into()];
    let narrowed = root.attenuate(&actual);
    let read = vec!["api.read".into()];
    let write = vec!["api.write".into()];
    assert!(p
        .authorize(
            &narrowed,
            "issuer",
            "client",
            "user",
            "userinfo",
            &actual,
            "api",
            Some(&write)
        )
        .is_err());
    let out = p
        .authorize(
            &narrowed, "issuer", "client", "user", "userinfo", &actual, "api", None,
        )
        .expect("default read");
    assert_eq!(out.0, read);
    assert!(p
        .authorize(
            &out.1,
            "issuer",
            "client",
            "user",
            "api",
            &read,
            "api",
            Some(&write)
        )
        .is_err());
    assert!(p
        .authorize(
            &out.1,
            "issuer",
            "client",
            "user",
            "api",
            &read,
            "api",
            Some(&read)
        )
        .is_ok());
    assert_eq!(
        root.capabilities.len(),
        2,
        "refresh grant retains original authority"
    );
}

#[test]
fn authority_binds_client_user_issuer_and_policy() {
    let p = policy();
    let scope = vec!["read".into()];
    let grant = p
        .capture(
            "issuer",
            "client",
            "user",
            "userinfo",
            &scope,
            &["api.read".into(), "api.write".into()],
        )
        .expect("authority");
    for (issuer, client, user) in [
        ("other", "client", "user"),
        ("issuer", "other", "user"),
        ("issuer", "client", "other"),
    ] {
        assert!(p
            .authorize(&grant, issuer, client, user, "userinfo", &scope, "api", None)
            .is_err());
    }
    let mut changed = p.clone();
    changed.rules[0].default_scopes = vec!["api.write".into()];
    assert!(changed
        .authorize(&grant, "issuer", "client", "user", "userinfo", &scope, "api", None)
        .is_err());
    assert!(p
        .capture(
            "issuer",
            "client",
            "user",
            "userinfo",
            &["openid".into()],
            &["api.read".into(), "api.write".into()]
        )
        .is_none());
}

#[test]
fn selectors_resolve_all_registered_aliases_without_normalization() {
    let p = policy();
    let selectors = vec![
        ("audience".into(), "api".into()),
        ("resource".into(), "https://api.example/resource?q=1".into()),
    ];
    assert_eq!(
        p.resolve_target(&selectors).expect("same target"),
        Some("api".into())
    );
    for pair in [
        ("audience", " api"),
        ("audience", "unknown"),
        ("resource", "https://api.example/resource?q=1#fragment"),
        ("resource", "api"),
    ] {
        assert!(p.resolve_target(&[(pair.0.into(), pair.1.into())]).is_err());
    }
    let mut two = p.clone();
    two.targets.push(ExchangeTarget {
        audience: "other".into(),
        resource_aliases: vec![],
    });
    assert!(two
        .resolve_target(&[
            ("audience".into(), "api".into()),
            ("audience".into(), "other".into())
        ])
        .is_err());
}

#[test]
fn policy_rejects_ambiguous_and_unbounded_or_unconditional_permissions() {
    let p = policy();
    for kind in 0..8 {
        let mut bad = p.clone();
        match kind {
            0 => bad.version = 2,
            1 => bad.targets.push(bad.targets[0].clone()),
            2 => bad.rules.push(bad.rules[0].clone()),
            3 => bad.rules[0].scopes[0].source_scopes.clear(),
            4 => bad.rules[0].default_scopes.push("unmapped".into()),
            5 => bad.targets[0]
                .resource_aliases
                .push("https://api.example/#f".into()),
            6 => bad.rules[0].scopes[0].target_scope = "openid".into(),
            _ => bad.rules[0].client_id = " ".into(),
        }
        assert!(bad.validate().is_err(), "case {kind}");
    }
}

#[test]
fn policy_rejects_cross_target_audience_alias_collision_in_either_order() {
    let mut p = policy();
    p.targets.push(ExchangeTarget {
        audience: p.targets[0].resource_aliases[0].clone(),
        resource_aliases: vec![],
    });
    assert!(p.validate().is_err());
    p.targets.reverse();
    assert!(p.validate().is_err());
}

#[test]
fn same_target_audience_and_resource_alias_remain_usable() {
    let mut p = policy();
    let audience = "https://api.example/resource?q=1";
    p.targets[0].audience = audience.into();
    for rule in &mut p.rules {
        rule.target_audience = audience.into();
    }
    p.validate().expect("same target is unambiguous");
    for selectors in [
        vec![("audience".into(), audience.into())],
        vec![("resource".into(), audience.into())],
        vec![
            ("audience".into(), audience.into()),
            ("resource".into(), audience.into()),
        ],
    ] {
        assert_eq!(p.resolve_target(&selectors), Ok(Some(audience.into())));
    }
}
