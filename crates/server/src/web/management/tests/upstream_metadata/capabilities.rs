use super::signing_capabilities::exercise;
use super::*;
use crate::oidc::capabilities::test_contract::*;
use crate::web::upstream_metadata::parse_upstream_discovery_body;

const OPERATIONS: [&str; 3] = ["authorize", "callback", "refresh"];

#[test]
fn upstream_capabilities_parser_checks_every_known_shape_before_optional_null_collapse(
) -> ManagementTestResult {
    run(async {
        let f = Fixture::new(0).await?;
        let baseline = serde_json::to_value(&f.discovery)?;
        for field in OP_ARRAYS {
            for value in [
                Value::Null,
                json!("secret-invalid"),
                json!(true),
                json!(42),
                json!({}),
                json!(["future", null]),
                json!([false]),
                json!([1]),
                json!([{}]),
                json!([[]]),
            ] {
                let mut raw = baseline.clone();
                raw[*field] = value;
                let error = parse_upstream_discovery_body(&serde_json::to_vec(&raw)?).unwrap_err();
                assert_eq!(
                    error,
                    format!("upstream discovery invalid capability field {field}")
                );
            }
            for value in [json!([]), json!(["future", "", "NONE", " none", "future"])] {
                let mut raw = baseline.clone();
                raw[*field] = value.clone();
                let parsed = parse_upstream_discovery_body(&serde_json::to_vec(&raw)?)?;
                assert_eq!(serde_json::to_value(parsed)?[*field], value);
            }
        }
        for field in OP_BOOLEANS {
            for value in [Value::Null, json!("false"), json!(0), json!([]), json!({})] {
                let mut raw = baseline.clone();
                raw[*field] = value;
                assert_eq!(
                    parse_upstream_discovery_body(&serde_json::to_vec(&raw)?).unwrap_err(),
                    format!("upstream discovery invalid capability field {field}")
                );
            }
            for value in [true, false] {
                let mut raw = baseline.clone();
                raw[*field] = json!(value);
                assert_eq!(
                    serde_json::to_value(parse_upstream_discovery_body(&serde_json::to_vec(
                        &raw
                    )?)?)?[*field],
                    value
                );
            }
        }
        let mut raw = baseline.clone();
        raw["unknown"] = Value::Null;
        raw["extension"] = json!({"nested":[null, {"scopes_supported":false}]});
        // Endpoint/key/alias null meaning is outside this capability admission rule.
        raw["registration_endpoint"] = Value::Null;
        raw["mtls_endpoint_aliases"] = Value::Null;
        assert!(parse_upstream_discovery_body(&serde_json::to_vec(&raw)?).is_ok());
        for duplicate in [
            br#"{"scopes_supported":[],"scopes_supported":null}"#.as_slice(),
            br#"{"extension":{"x":1,"x":2}}"#.as_slice(),
        ] {
            assert_eq!(
                parse_upstream_discovery_body(duplicate).unwrap_err(),
                "upstream discovery response contains duplicate object keys"
            );
        }
        assert!(parse_upstream_discovery_body(&serde_json::to_vec(&baseline)?).is_ok());
        Ok(())
    })
}

#[test]
fn upstream_capabilities_parser_scopes_none_and_preserves_omission() -> ManagementTestResult {
    run(async {
        let f = Fixture::new(0).await?;
        let baseline = serde_json::to_value(&f.discovery)?;
        for field in AUTH_ARRAYS {
            let mut raw = baseline.clone();
            raw.as_object_mut().unwrap().remove(*field);
            let parsed = parse_upstream_discovery_body(&serde_json::to_vec(&raw)?)?;
            assert!(serde_json::to_value(parsed)?.get(*field).is_none());
            for (value, allowed) in [
                (json!(["none"]), false),
                (json!(["RS256", "none"]), false),
                (json!(["NONE", " none", "none ", "None", "RS384"]), true),
                (json!([]), true),
            ] {
                raw[*field] = value;
                assert_eq!(
                    parse_upstream_discovery_body(&serde_json::to_vec(&raw)?).is_ok(),
                    allowed
                );
            }
        }
        for field in [
            "id_token_signing_alg_values_supported",
            "userinfo_signing_alg_values_supported",
            "request_object_signing_alg_values_supported",
        ] {
            let mut raw = baseline.clone();
            raw[field] = json!(["none"]);
            assert!(parse_upstream_discovery_body(&serde_json::to_vec(&raw)?).is_ok());
        }
        Ok(())
    })
}

#[test]
fn upstream_capabilities_operations_recheck_typed_cache_auth_arrays_before_replacement(
) -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for field in AUTH_ARRAYS {
                for signed_replacement in [false, true] {
                    for value in [
                        None,
                        Some(vec![]),
                        Some(vec!["RS384".to_string(), "NONE".into(), " none".into()]),
                        Some(vec!["none".to_string()]),
                    ] {
                        let mut f = Fixture::new(0).await?;
                        let chain = f.chain(f.metadata(), &[], None);
                        if signed_replacement {
                            f.configure(&chain).await?;
                        }
                        match *field {
                            "token_endpoint_auth_signing_alg_values_supported" => {
                                f.discovery.token_endpoint_auth_signing_alg_values_supported =
                                    value.clone()
                            }
                            "revocation_endpoint_auth_signing_alg_values_supported" => {
                                f.discovery
                                    .revocation_endpoint_auth_signing_alg_values_supported =
                                    value.clone()
                            }
                            "introspection_endpoint_auth_signing_alg_values_supported" => {
                                f.discovery
                                    .introspection_endpoint_auth_signing_alg_values_supported =
                                    value.clone()
                            }
                            _ => unreachable!(),
                        }
                        f.reset_discovery()?;
                        let allowed = !value.is_some_and(|v| v.iter().any(|s| s == "none"));
                        let error =
                            "upstream discovery authentication signing capabilities invalid";
                        exercise(
                            &f,
                            operation,
                            signed_replacement.then_some(&chain),
                            allowed,
                            usize::from(signed_replacement && allowed),
                            "RS256",
                            (!allowed).then_some(error),
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
fn upstream_capabilities_signed_operations_reject_original_and_derived_auth_none(
) -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for cached in [false, true] {
                for field in AUTH_ARRAYS {
                    for case in ["original", "overlay", "removal", "derived", "valid"] {
                        let f = Fixture::new(1).await?;
                        let mut metadata = f.metadata();
                        let mut overlay = None;
                        let mut policies = vec![None, None];
                        match case {
                            "valid" => {
                                metadata[*field] = json!(["RS384", "NONE", " none", "RS384"])
                            }
                            "derived" => {
                                policies[1] =
                                    Some(json!({"openid_provider":{(*field):{"value":["none"]}}}))
                            }
                            _ => {
                                metadata[*field] = json!(["none"]);
                                if case == "overlay" {
                                    overlay = Some(json!({(*field):["RS384"]}));
                                }
                                if case == "removal" {
                                    policies[1] =
                                        Some(json!({"openid_provider":{(*field):{"value":null}}}));
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
            }
        }
        Ok(())
    })
}

#[test]
fn upstream_capabilities_raw_fetch_refuses_without_cache_state_or_token_effects(
) -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for (field, value) in [
                ("scopes_supported", Value::Null),
                ("request_parameter_supported", Value::Null),
                ("claims_supported", json!(["email", 1])),
                (
                    "token_endpoint_auth_signing_alg_values_supported",
                    json!(["none"]),
                ),
                (
                    "revocation_endpoint_auth_signing_alg_values_supported",
                    json!(["none"]),
                ),
                (
                    "introspection_endpoint_auth_signing_alg_values_supported",
                    json!(["none"]),
                ),
            ] {
                let mut f = Fixture::new(0).await?;
                let mut raw = f.metadata();
                raw[field] = value;
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                f.request.issuer = format!("http://{}", listener.local_addr()?);
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
                let error = format!("upstream discovery invalid capability field {field}");
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
