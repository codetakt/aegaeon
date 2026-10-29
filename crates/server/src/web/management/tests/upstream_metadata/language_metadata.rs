use super::signing_capabilities::exercise;
use super::*;
use crate::web::upstream_metadata::parse_upstream_discovery_body;

#[test]
fn language_discovery_raw_and_typed_cache_precede_signed_replacement_and_live_use(
) -> ManagementTestResult {
    run(async {
        for operation in ["authorize", "callback", "refresh"] {
            for field in ["ui_locales_supported", "claims_locales_supported"] {
                for replacement in [false, true] {
                    for (tags, allowed) in [
                        (None, true),
                        (Some(vec![]), true),
                        (Some(vec!["en", "EN", "x-private"]), true),
                        (Some(vec!["en_US"]), false),
                        (Some(vec!["eng"]), false),
                    ] {
                        let mut f = Fixture::new(0).await?;
                        let chain = f.chain(f.metadata(), &[], None);
                        if replacement {
                            f.configure(&chain).await?;
                        }
                        if operation == "refresh" {
                            f.respond(None)?;
                        }
                        let tags = tags
                            .map(|tags| tags.into_iter().map(str::to_owned).collect::<Vec<_>>());
                        if field == "ui_locales_supported" {
                            f.discovery.ui_locales_supported = tags;
                        } else {
                            f.discovery.claims_locales_supported = tags;
                        }
                        let raw = serde_json::to_vec(&f.discovery)?;
                        assert_eq!(parse_upstream_discovery_body(&raw).is_ok(), allowed);
                        f.reset_discovery()?;
                        exercise(
                            &f,
                            operation,
                            replacement.then_some(&chain),
                            allowed,
                            usize::from(replacement && allowed),
                            "RS256",
                            (!allowed)
                                .then_some("upstream discovery language capabilities invalid"),
                        )
                        .await?;
                    }
                }
            }
        }
        Ok(())
    })
}

#[test]
fn language_signed_fresh_and_cache_operations_check_originals_names_and_policy_results(
) -> ManagementTestResult {
    run(async {
        for operation in ["authorize", "callback", "refresh"] {
            for cached in [false, true] {
                for (field, bad, good) in [
                    ("ui_locales_supported", json!(["eng"]), json!(["en", "EN"])),
                    ("display_name#en", json!([]), json!("Name")),
                ] {
                    for case in [
                        "original", "overlay", "removal", "value", "default", "add", "valid",
                    ] {
                        if case == "add" && field != "ui_locales_supported" {
                            continue;
                        }
                        let f = Fixture::new(1).await?;
                        if operation == "refresh" {
                            f.respond(None)?;
                        }
                        let mut metadata = f.metadata();
                        let mut policies = vec![None, None];
                        let mut overlay = None;
                        match case {
                            "valid" => {
                                metadata[field] = good.clone();
                            }
                            "value" | "default" | "add" => {
                                policies[1] =
                                    Some(json!({"openid_provider":{(field):{(case):bad}}}));
                            }
                            _ => {
                                metadata[field] = bad.clone();
                                if case == "overlay" {
                                    overlay = Some(json!({(field):good}));
                                }
                                if case == "removal" {
                                    policies[1] =
                                        Some(json!({"openid_provider":{(field):{"value":null}}}));
                                }
                            }
                        }
                        let chain = f.chain(metadata, &policies, overlay);
                        f.configure(&chain).await?;
                        if cached {
                            cache(&f.state, &chain).await?;
                        }
                        let allowed = case == "valid";
                        exercise(
                            &f,
                            operation,
                            Some(&chain),
                            allowed,
                            usize::from(!cached || !allowed),
                            "RS256",
                            None,
                        )
                        .await?;
                    }
                }
                let f = Fixture::new(0).await?;
                if operation == "refresh" {
                    f.respond(None)?;
                }
                let chain = f.chain(
                    f.metadata(),
                    &[Some(
                        json!({"openid_provider":{"display_name#en_US":{"essential":false}}}),
                    )],
                    None,
                );
                f.configure(&chain).await?;
                if cached {
                    cache(&f.state, &chain).await?;
                }
                exercise(&f, operation, Some(&chain), false, 1, "RS256", None).await?;
            }
        }
        Ok(())
    })
}

#[test]
fn language_ordinary_discovery_suffixes_stay_extensions() -> ManagementTestResult {
    run(async {
        let f = Fixture::new(0).await?;
        let mut raw = f.metadata();
        raw["display_name#en_US"] = json!([]);
        raw["service_documentation#eng"] = json!(false);
        assert!(parse_upstream_discovery_body(&serde_json::to_vec(&raw)?).is_ok());
        for field in ["ui_locales_supported", "claims_locales_supported"] {
            raw[field] = json!(["en-US", "EN-us", "x-a-a"]);
        }
        let parsed = parse_upstream_discovery_body(&serde_json::to_vec(&raw)?)?;
        assert_eq!(
            parsed.ui_locales_supported,
            Some(vec!["en-US".into(), "EN-us".into(), "x-a-a".into()])
        );
        Ok(())
    })
}
