use super::signing_capabilities::exercise;
use super::*;

#[test]
fn protocol_keys_signed_metadata_checks_originals_and_policy_before_live_operations(
) -> ManagementTestResult {
    run(async {
        for operation in ["authorize", "callback", "refresh"] {
            for case in [
                "valid", "overlay", "removal", "derived", "default", "partial",
            ] {
                let f = Fixture::new(1).await?;
                let mut metadata = f.metadata();
                metadata["signed_jwks_uri"] =
                    json!("https://unfetched.example/keys.jwt?revision=1");
                let mut overlay = None;
                let mut policies = vec![None, None];
                match case {
                    "overlay" | "removal" => {
                        metadata["jwks"] = json!({"keys":[{"kty":"future","d":null}]});
                        if case == "overlay" {
                            overlay = Some(json!({"jwks":f.jwks}));
                        } else {
                            policies[1] = Some(json!({"openid_provider":{"jwks":{"value":null}}}));
                        }
                    }
                    "derived" => {
                        policies[1] =
                            Some(json!({"openid_provider":{"jwks":{"value":{"keys":false}}}}))
                    }
                    "default" => {
                        metadata.as_object_mut().unwrap().remove("jwks");
                        policies[1] = Some(json!({"openid_provider":{"jwks":{"default":f.jwks}}}));
                    }
                    "partial" => {
                        metadata.as_object_mut().unwrap().remove("jwks_uri");
                        overlay = Some(json!({"jwks_uri":f.discovery.jwks_uri}));
                    }
                    _ => {}
                }
                let chain = f.chain(metadata, &policies, overlay);
                f.configure(&chain).await?;
                let allowed = matches!(case, "valid" | "default" | "partial");
                exercise(&f, operation, Some(&chain), allowed, 1, "RS256", None).await?;
                assert_eq!(f.key_calls(), 0);
            }
        }
        Ok(())
    })
}

async fn key_operation(
    f: &Fixture,
    operation: &str,
    chain: &ResolvedTrustChain,
) -> Result<(), axum::response::Response> {
    let acquire = |_: Vec<TrustAnchor>, _: i64| std::future::ready(Ok(chain.clone()));
    if operation == "callback" {
        perform_upstream_callback_exchange_with(
            &f.state,
            &f.request,
            "code",
            "https://local.example",
            acquire,
        )
        .await
        .map(|_| ())
    } else {
        let link = f.refresh_link();
        let exchange = perform_upstream_refresh_exchange_with(
            &f.state,
            "https://local.example",
            &link,
            &f.profile,
            acquire,
        )
        .await?;
        validate_upstream_refresh_exchange(&f.state, "https://local.example", &link, &exchange)
            .await
    }
}

#[test]
fn protocol_keys_live_tls_fetch_and_raw_cache_apply_same_profile_and_constraints(
) -> ManagementTestResult {
    run(async {
        for operation in ["callback", "refresh"] {
            for cached in [false, true] {
                for case in ["mixed", "private", "duplicate", "wider", "missing", "empty"] {
                    let f = Fixture::new(0).await?;
                    let mut raw = f.jwks.clone();
                    let mut metadata = f.metadata();
                    match case {
                        "mixed" => raw["keys"].as_array_mut().unwrap().extend([
                            Value::Null,
                            json!({"kty":"future","kid":"unusable","extension":{"d":null}}),
                        ]),
                        "private" => raw["keys"]
                            .as_array_mut()
                            .unwrap()
                            .push(json!({"kty":"future","d":null})),
                        "duplicate" => raw["keys"]
                            .as_array_mut()
                            .unwrap()
                            .push(json!({"kty":"future","kid":"op-key"})),
                        "wider" => metadata["jwks"]["keys"][0]["alg"] = json!("RS256"),
                        "missing" => {
                            metadata.as_object_mut().unwrap().remove("jwks_uri");
                        }
                        "empty" => raw["keys"] = json!([]),
                        _ => unreachable!(),
                    }
                    if cached {
                        f.state
                            .upstream
                            .jwks_cache
                            .try_insert(&f.discovery.jwks_uri, raw.clone())?;
                    } else {
                        f.state
                            .upstream
                            .jwks_cache
                            .try_invalidate(&f.discovery.jwks_uri)?;
                        f.serve_jwks(raw.clone());
                    }
                    let chain = f.chain(metadata, &[], None);
                    f.configure(&chain).await?;
                    let result = key_operation(&f, operation, &chain).await;
                    assert_eq!(
                        result.is_ok(),
                        case == "mixed",
                        "{operation} {cached} {case}"
                    );
                    assert_eq!(f.key_calls(), usize::from(!cached && case != "missing"));
                    if case == "mixed" {
                        assert_eq!(
                            f.state.upstream.jwks_cache.try_get(&f.discovery.jwks_uri)?,
                            Some(raw)
                        );
                    }
                    if let Err(response) = result {
                        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
                        let text = String::from_utf8(
                            axum::body::to_bytes(response.into_body(), 4096)
                                .await?
                                .to_vec(),
                        )?;
                        assert!(!text.contains("op-key"));
                    }
                }
            }
        }
        Ok(())
    })
}

#[test]
fn protocol_keys_refresh_without_id_token_does_not_consume_keys() -> ManagementTestResult {
    run(async {
        let f = Fixture::new(0).await?;
        f.respond(None)?;
        f.state
            .upstream
            .jwks_cache
            .try_insert(&f.discovery.jwks_uri, json!({"keys":[{"d":"forbidden"}]}))?;
        let chain = f.chain(f.metadata(), &[], None);
        f.configure(&chain).await?;
        key_operation(&f, "refresh", &chain)
            .await
            .map_err(response_error)?;
        assert_eq!(f.key_calls(), 0);
        Ok(())
    })
}

#[test]
fn protocol_keys_ordinary_discovery_keeps_unknown_extensions_uninterpreted() -> ManagementTestResult
{
    run(async {
        let f = Fixture::new(0).await?;
        let mut raw = serde_json::to_value(&f.discovery)?;
        raw["jwks"] = json!({"keys":[{"d":"opaque"}]});
        raw["signed_jwks_uri"] = json!(false);
        let admitted = crate::web::upstream_metadata::parse_upstream_discovery_body(
            &serde_json::to_vec(&raw)?,
        )?;
        assert_eq!(admitted.jwks_uri, f.discovery.jwks_uri);
        assert!(serde_json::to_value(admitted)?.get("jwks").is_none());
        assert_eq!(f.key_calls(), 0);
        Ok(())
    })
}
