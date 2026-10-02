use super::signing_capabilities::exercise;
use super::*;
use crate::oidc::provider_urls::test_contract::*;
use crate::web::upstream_metadata::parse_upstream_discovery_body;
const OPERATIONS: [&str; 3] = ["authorize", "callback", "refresh"];

#[test]
fn upstream_urls_parser_checks_all_fields_before_optional_null_collapse() -> ManagementTestResult {
    run(async {
        let f = Fixture::new(0).await?;
        let baseline = serde_json::to_value(&f.discovery)?;
        for field in OP_ENDPOINTS
            .iter()
            .chain(INFORMATIONAL)
            .chain(["issuer"].iter())
        {
            let mut bad = if INFORMATIONAL.contains(field) {
                bad_urls()
            } else {
                bad_endpoints()
            };
            if *field == "issuer" {
                bad.extend([
                    json!("https://issuer.example/?"),
                    json!("https://issuer.example/?q=1"),
                ]);
            }
            for value in bad {
                let mut raw = baseline.clone();
                raw[*field] = value;
                assert_eq!(
                    parse_upstream_discovery_body(&serde_json::to_vec(&raw)?).unwrap_err(),
                    format!("upstream discovery invalid URL field {field}")
                );
            }
            let good = if INFORMATIONAL.contains(field) {
                vec![
                    "urn:example:policy",
                    "http://user:pass@docs.example/path?q=1#",
                    "mailto:policy@example.com",
                ]
            } else if *field == "issuer" {
                vec!["HTTPS://Issuer.example:8443/path"]
            } else {
                GOOD_ENDPOINTS.to_vec()
            };
            for value in good {
                let mut raw = baseline.clone();
                raw[*field] = json!(value);
                let parsed = parse_upstream_discovery_body(&serde_json::to_vec(&raw)?)?;
                assert_eq!(serde_json::to_value(parsed)?[*field], value);
            }
            if ![
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "jwks_uri",
            ]
            .contains(field)
            {
                let mut raw = baseline.clone();
                raw.as_object_mut().unwrap().remove(*field);
                assert!(parse_upstream_discovery_body(&serde_json::to_vec(&raw)?).is_ok());
            }
        }
        let mut raw = baseline;
        raw["extension"] = json!({"nested":[null,{"token_endpoint":false}]});
        raw["scopes_supported"] = json!([]);
        assert_eq!(
            parse_upstream_discovery_body(&serde_json::to_vec(&raw)?)?.scopes_supported,
            Some(vec![])
        );
        Ok(())
    })
}

#[test]
fn upstream_urls_raw_alias_maps_and_unknown_only_typed_projection() -> ManagementTestResult {
    run(async {
        let f = Fixture::new(0).await?;
        let baseline = serde_json::to_value(&f.discovery)?;
        for value in [
            Value::Null,
            json!({}),
            json!([]),
            json!(false),
            json!(42),
            json!("https://provider.example"),
        ] {
            let mut raw = baseline.clone();
            raw["mtls_endpoint_aliases"] = value;
            assert_eq!(
                parse_upstream_discovery_body(&serde_json::to_vec(&raw)?).unwrap_err(),
                "upstream discovery invalid URL field mtls_endpoint_aliases"
            );
        }
        for field in OP_ALIASES {
            for value in bad_endpoints() {
                let mut raw = baseline.clone();
                raw["mtls_endpoint_aliases"] = json!({(*field):value,"future":null});
                assert_eq!(
                    parse_upstream_discovery_body(&serde_json::to_vec(&raw)?).unwrap_err(),
                    "upstream discovery invalid URL field mtls_endpoint_aliases"
                );
            }
            for value in GOOD_ENDPOINTS {
                let mut raw = baseline.clone();
                raw["mtls_endpoint_aliases"] = json!({(*field):value,"future":{"nested":null}});
                let typed = parse_upstream_discovery_body(&serde_json::to_vec(&raw)?)?;
                assert!(crate::oidc::provider_urls::validate_typed(&typed).is_ok());
            }
        }
        for operation in OPERATIONS {
            let mut f = Fixture::new(0).await?;
            let mut raw = serde_json::to_value(&f.discovery)?;
            raw["mtls_endpoint_aliases"] = json!({"future":null,"authorization_endpoint":{},"unknown_endpoint":{"nested":null}});
            f.discovery = parse_upstream_discovery_body(&serde_json::to_vec(&raw)?)?;
            assert_eq!(
                serde_json::to_value(&f.discovery)?["mtls_endpoint_aliases"],
                json!({})
            );
            f.reset_discovery()?;
            exercise(&f, operation, None, true, 0, "RS256", None).await?;
        }
        Ok(())
    })
}

#[test]
fn upstream_urls_typed_cache_refuses_all_retained_fields_before_signed_replacement(
) -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for signed in [false, true] {
                for (field, alias) in OP_ENDPOINTS
                    .iter()
                    .chain(INFORMATIONAL)
                    .chain(["issuer"].iter())
                    .map(|field| (*field, false))
                    .chain(
                        [
                            "token_endpoint",
                            "revocation_endpoint",
                            "introspection_endpoint",
                            "pushed_authorization_request_endpoint",
                        ]
                        .map(|field| (field, true)),
                    )
                {
                    let mut f = Fixture::new(0).await?;
                    let chain = f.chain(f.metadata(), &[], None);
                    if signed {
                        f.configure(&chain).await?;
                    }
                    let mut raw = serde_json::to_value(&f.discovery)?;
                    if alias {
                        raw["mtls_endpoint_aliases"] = json!({(field):"relative"});
                    } else {
                        raw[field] = json!("relative");
                    }
                    // Simulate a legacy typed cache, without passing the new raw parser.
                    f.discovery = serde_json::from_value(raw)?;
                    f.reset_discovery()?;
                    exercise(
                        &f,
                        operation,
                        signed.then_some(&chain),
                        false,
                        0,
                        "RS256",
                        Some("upstream discovery URL metadata invalid"),
                    )
                    .await?;
                }
            }
        }
        Ok(())
    })
}

#[test]
fn upstream_urls_signed_original_derived_and_partial_completion_controls() -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for cached in [false, true] {
                for alias in [false, true] {
                    for case in [
                        "original", "overlay", "removal", "derived", "default", "superior", "valid",
                    ] {
                        let f = Fixture::new(1).await?;
                        let field = if alias {
                            "mtls_endpoint_aliases"
                        } else {
                            "registration_endpoint"
                        };
                        let good = if alias {
                            json!({"future":null})
                        } else {
                            json!("HTTPS://Registration.example:8443/path?mode=explicit")
                        };
                        let bad = if alias {
                            json!({"device_authorization_endpoint":null})
                        } else {
                            json!("http://registration.example")
                        };
                        let mut metadata = f.metadata();
                        let mut overlay = None;
                        let mut policies = vec![None, None];
                        match case {
                            "valid" => metadata[field] = good.clone(),
                            "derived" => {
                                policies[1] =
                                    Some(json!({"openid_provider":{(field):{"value":bad}}}))
                            }
                            "default" => {
                                policies[1] =
                                    Some(json!({"openid_provider":{(field):{"default":good}}}))
                            }
                            "superior" => overlay = Some(json!({(field):good})),
                            _ => {
                                metadata[field] = bad;
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
                        let originals = chain.chain_jwts.clone();
                        f.configure(&chain).await?;
                        if cached {
                            cache(&f.state, &chain).await?;
                        }
                        let allowed = matches!(case, "valid" | "default" | "superior");
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
                        assert_eq!(chain.chain_jwts, originals);
                    }
                }
            }
        }
        Ok(())
    })
}

#[test]
fn upstream_urls_schema_query_acceptance_does_not_authorize_outbound_query() -> ManagementTestResult
{
    run(async {
        for operation in OPERATIONS {
            let mut f = Fixture::new(0).await?;
            let field = if operation == "authorize" {
                "authorization_endpoint"
            } else {
                "token_endpoint"
            };
            let mut raw = serde_json::to_value(&f.discovery)?;
            raw[field] = json!(format!("{}?query=1", raw[field].as_str().unwrap()));
            f.discovery = parse_upstream_discovery_body(&serde_json::to_vec(&raw)?)?;
            f.reset_discovery()?;
            let error = format!("{field} must not include query or fragment");
            exercise(&f, operation, None, false, 0, "RS256", Some(&error)).await?;
        }
        Ok(())
    })
}

#[test]
fn upstream_urls_raw_fetch_refuses_without_cache_state_or_token_effects() -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for (field, value) in [
                ("registration_endpoint", Value::Null),
                ("token_endpoint", json!("http://provider.example")),
                ("op_policy_uri", json!("relative")),
                ("mtls_endpoint_aliases", json!({})),
                ("mtls_endpoint_aliases", json!({"userinfo_endpoint":null})),
            ] {
                let mut f = Fixture::new(0).await?;
                let mut raw = f.metadata();
                raw[field] = value;
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let tls = TlsRelay::new(listener.local_addr()?, "example.com")?;
                f.state.upstream.test_http_client = Some(tls.client.clone());
                f.request.issuer = tls.endpoint.clone();
                let calls = Arc::new(AtomicUsize::new(0));
                let observed = calls.clone();
                let app = Router::new().fallback(axum::routing::get(move || {
                    observed.fetch_add(1, Ordering::SeqCst);
                    let body = raw.clone();
                    async move { Json(body) }
                }));
                let task = tokio::spawn(async move {
                    axum::serve(listener, app).await.unwrap();
                });
                let error = format!("upstream discovery invalid URL field {field}");
                exercise(&f, operation, None, false, 0, "RS256", Some(&error)).await?;
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert!(f
                    .state
                    .upstream
                    .discovery_cache
                    .try_get(&f.request.issuer)?
                    .is_none());
                task.abort();
            }
        }
        Ok(())
    })
}
