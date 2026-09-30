use super::*;
use crate::policy::token_exchange::{ExchangeTarget, TokenExchangePolicy};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> (ClientCredentialsPolicy, TokenExchangePolicy) {
    let catalog = TokenExchangePolicy {
        targets: vec![ExchangeTarget {
            audience: "orders-api".into(),
            resource_aliases: vec!["https://orders.example/api".into()],
        }],
        ..TokenExchangePolicy::default()
    };
    let policy = ClientCredentialsPolicy {
        resource_servers: vec![ClientCredentialsResourceServer {
            target_audience: "orders-api".into(),
            introspection_clients: vec!["orders-resource-server".into()],
        }],
        rules: vec![ClientCredentialsRule {
            client_id: "orders-worker".into(),
            target_audience: "orders-api".into(),
            scopes: vec!["orders.read".into(), "orders.write".into()],
            default_scopes: vec!["orders.read".into()],
            default_target: false,
        }],
        ..ClientCredentialsPolicy::default()
    };
    (policy, catalog)
}

fn params(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(key, value)| ((*key).into(), (*value).into()))
        .collect()
}

#[test]
fn logical_and_uri_selection_require_the_same_explicit_authority() {
    let (policy, catalog) = fixture();
    for selection in [
        params(&[("audience", "orders-api")]),
        params(&[("resource", "https://orders.example/api")]),
        params(&[
            ("audience", "orders-api"),
            ("resource", "https://orders.example/api"),
        ]),
    ] {
        let issued = policy
            .authorize(
                &catalog,
                "orders-worker",
                &["orders.read".into()],
                &selection,
                None,
            )
            .expect("explicit rule and current client ceiling authorize read");
        assert_eq!(issued.audience, "orders-api");
        assert_eq!(issued.scopes, ["orders.read"]);
        assert_eq!(issued.introspection_clients, ["orders-resource-server"]);
        assert_eq!(
            policy.authorize(
                &catalog,
                "other-client",
                &["orders.read".into()],
                &selection,
                None
            ),
            Err(ClientCredentialsAuthorizationError::InvalidTarget)
        );
    }
}

#[test]
fn missing_policy_and_implicit_target_authority_are_denied() {
    let (mut policy, catalog) = fixture();
    let scopes = ["orders.read".into()];
    assert_eq!(
        ClientCredentialsPolicy::default().authorize(
            &catalog,
            "orders-worker",
            &scopes,
            &params(&[("audience", "orders-api")]),
            None
        ),
        Err(ClientCredentialsAuthorizationError::InvalidTarget)
    );
    assert_eq!(
        policy.authorize(&catalog, "orders-worker", &scopes, &[], None),
        Err(ClientCredentialsAuthorizationError::InvalidTarget)
    );
    policy.rules[0].default_target = true;
    assert!(policy
        .authorize(&catalog, "orders-worker", &scopes, &[], None)
        .is_ok());
    policy.rules[0].default_scopes.clear();
    assert_eq!(
        policy.authorize(&catalog, "orders-worker", &scopes, &[], None),
        Err(ClientCredentialsAuthorizationError::InvalidScope)
    );
    assert!(policy
        .authorize(&catalog, "orders-worker", &scopes, &[], Some("orders.read"))
        .is_ok());
}

#[test]
fn duplicate_unknown_and_conflicting_selectors_fail_closed() {
    let (policy, mut catalog) = fixture();
    catalog.targets.push(ExchangeTarget {
        audience: "other-api".into(),
        resource_aliases: vec!["https://other.example/api".into()],
    });
    for selection in [
        params(&[("audience", "orders-api"), ("audience", "orders-api")]),
        params(&[
            ("resource", "https://orders.example/api"),
            ("resource", "https://orders.example/api"),
        ]),
        params(&[
            ("audience", "orders-api"),
            ("resource", "https://other.example/api"),
        ]),
        params(&[("audience", "orders-worker")]),
        params(&[("resource", "https://unregistered.example/api")]),
        params(&[("audience", "other-api")]),
    ] {
        assert_eq!(
            policy.authorize(
                &catalog,
                "orders-worker",
                &["orders.read".into()],
                &selection,
                None
            ),
            Err(ClientCredentialsAuthorizationError::InvalidTarget)
        );
    }
}

#[test]
fn explicit_and_default_scopes_are_bounded_by_rule_and_registration() {
    let (mut policy, catalog) = fixture();
    policy.rules[0].default_target = true;
    for requested in [None, Some("orders.read")] {
        assert_eq!(
            policy.authorize(
                &catalog,
                "orders-worker",
                &["orders.write".into()],
                &[],
                requested
            ),
            Err(ClientCredentialsAuthorizationError::InvalidScope)
        );
    }
    for requested in [
        "",
        "orders.read orders.read",
        "orders.read  orders.write",
        "openid",
        "extra",
    ] {
        assert_eq!(
            policy.authorize(
                &catalog,
                "orders-worker",
                &["orders.read".into(), "extra".into()],
                &[],
                Some(requested)
            ),
            Err(ClientCredentialsAuthorizationError::InvalidScope)
        );
    }
}

#[test]
fn selected_context_survives_unrelated_changes_but_tracks_its_authority() {
    let (policy, catalog) = fixture();
    let original = policy
        .selected_context(&catalog, "orders-worker", "orders-api")
        .expect("context");
    let mut unrelated = catalog.clone();
    unrelated.targets.push(ExchangeTarget {
        audience: "other-api".into(),
        resource_aliases: vec![],
    });
    assert_eq!(
        policy
            .selected_context(&unrelated, "orders-worker", "orders-api")
            .expect("context"),
        original
    );
    let mut reordered = policy.clone();
    reordered.rules[0].scopes.reverse();
    assert_eq!(
        reordered
            .selected_context(&catalog, "orders-worker", "orders-api")
            .expect("context"),
        original
    );
    let mut changed = policy.clone();
    changed.resource_servers[0].introspection_clients.clear();
    assert_ne!(
        changed
            .selected_context(&catalog, "orders-worker", "orders-api")
            .expect("context")
            .context_digest,
        original.context_digest
    );
    let mut changed = policy.clone();
    changed.rules[0].default_target = true;
    assert_ne!(
        changed
            .selected_context(&catalog, "orders-worker", "orders-api")
            .expect("context")
            .context_digest,
        original.context_digest
    );
    let mut changed = catalog.clone();
    changed.targets[0]
        .resource_aliases
        .push("https://orders.example/alias".into());
    assert_ne!(
        policy
            .selected_context(&changed, "orders-worker", "orders-api")
            .expect("context")
            .context_digest,
        original.context_digest
    );
}

#[test]
fn validation_requires_explicit_binding_and_unambiguous_bounded_authority() -> TestResult {
    let (policy, catalog) = fixture();
    let initial = serde_json::to_value(&policy)?;
    for (field, replacement) in [
        ("resourceServers", serde_json::json!([])),
        (
            "resourceServers",
            serde_json::json!([{"targetAudience":"orders-api","introspectionClients":["rs","rs"]}]),
        ),
        ("version", serde_json::json!(2)),
    ] {
        let mut invalid = initial.clone();
        invalid[field] = replacement;
        assert!(serde_json::from_value::<ClientCredentialsPolicy>(invalid)?
            .validate(&catalog)
            .is_err());
    }
    for scopes in [
        vec![],
        vec!["openid"],
        vec!["offline_access"],
        vec!["orders.read", "orders.read"],
        vec!["bad scope"],
    ] {
        let mut invalid = policy.clone();
        invalid.rules[0].scopes = scopes.into_iter().map(str::to_owned).collect();
        assert!(invalid.validate(&catalog).is_err());
    }
    let mut duplicate = policy.clone();
    duplicate.rules.push(duplicate.rules[0].clone());
    assert!(duplicate.validate(&catalog).is_err());
    let mut empty_binding = policy;
    empty_binding.resource_servers[0]
        .introspection_clients
        .clear();
    assert!(empty_binding.validate(&catalog).is_ok());
    Ok(())
}
