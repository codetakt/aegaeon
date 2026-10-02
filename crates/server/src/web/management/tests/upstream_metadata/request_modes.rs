use super::*;
use crate::web::upstream_authorize::complete_upstream_authorize_with;
use crate::web::upstream_metadata::parse_upstream_discovery_body;

const FLAGS: [&str; 2] = [
    "require_pushed_authorization_requests",
    "require_signed_request_object",
];

async fn check_authorize_result(
    f: &Fixture,
    response: axum::response::Response,
    allowed: bool,
) -> ManagementTestResult {
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.state.upstream.auth_store.pending_count_for_tests()?,
        usize::from(allowed)
    );
    if allowed {
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = url::Url::parse(response.headers()["location"].to_str()?)?;
        let params: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(params["response_type"], "code");
        assert!(!params.contains_key("request") && !params.contains_key("request_uri"));
        let request = f
            .state
            .upstream
            .auth_store
            .try_consume_async(params["state"].clone())
            .await?;
        assert!(request.is_some());
        assert_eq!(f.state.upstream.auth_store.pending_count_for_tests()?, 0);
    } else {
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(!response.headers().contains_key("location"));
        let body = axum::body::to_bytes(response.into_body(), 4096).await?;
        let error: Value = serde_json::from_slice(&body)?;
        assert_eq!(error["error"], "server_error");
        assert!(f.state.upstream.discovery_cache.try_get(ISSUER)?.is_none());
    }
    Ok(())
}

#[test]
fn upstream_request_modes_parser_requires_present_booleans() -> ManagementTestResult {
    run(async {
        let f = Fixture::new(0).await?;
        assert_eq!(f.discovery.require_signed_request_object, None);
        let mut baseline = serde_json::to_value(&f.discovery)?;
        for field in FLAGS {
            baseline.as_object_mut().unwrap().remove(field);
        }
        for field in FLAGS {
            for value in [None, Some(false), Some(true)] {
                let mut input = baseline.clone();
                if let Some(value) = value {
                    input[field] = json!(value);
                }
                let parsed = parse_upstream_discovery_body(&serde_json::to_vec(&input)?)?;
                let output = serde_json::to_value(&parsed)?;
                assert_eq!(output.get(field), value.map(Value::Bool).as_ref());
                assert_eq!(
                    serde_json::from_value::<OidcDiscovery>(output.clone())
                        .map(|v| serde_json::to_value(v).unwrap())?,
                    output
                );
            }
            for value in [Value::Null, json!("true"), json!(1), json!([]), json!({})] {
                let mut input = baseline.clone();
                input[field] = value;
                assert!(parse_upstream_discovery_body(&serde_json::to_vec(&input)?).is_err());
                assert!(serde_json::from_value::<OidcDiscovery>(input).is_err());
            }
            let mut input = baseline.clone();
            input[field] = json!(false);
            let serialized = serde_json::to_string(&input)?;
            let duplicate = format!(
                "{},\"{field}\":true}}",
                serialized.strip_suffix('}').unwrap()
            );
            assert!(parse_upstream_discovery_body(duplicate.as_bytes()).is_err());
        }
        baseline["future_extension"] = json!({"value":true});
        assert!(parse_upstream_discovery_body(&serde_json::to_vec(&baseline)?).is_ok());
        Ok(())
    })
}

#[test]
fn upstream_request_modes_guard_real_authorize_state_and_redirect() -> ManagementTestResult {
    run(async {
        for route in ["ordinary", "fresh", "cached"] {
            for (par, jar) in [
                (None, None),
                (Some(false), Some(false)),
                (Some(true), None),
                (None, Some(true)),
                (Some(true), Some(true)),
            ] {
                let mut f = Fixture::new(usize::from(route != "ordinary")).await?;
                f.discovery.require_pushed_authorization_requests =
                    if route == "ordinary" { par } else { None };
                f.discovery.require_signed_request_object =
                    if route == "ordinary" { jar } else { None };
                f.discovery.request_parameter_supported = Some(true);
                // PAR endpoint and Request Object support alone remain compatible.
                f.reset_discovery()?;
                let mut metadata = f.metadata();
                for (field, value) in FLAGS.into_iter().zip([par, jar]) {
                    if let Some(value) = value {
                        metadata[field] = json!(value);
                    } else {
                        metadata.as_object_mut().unwrap().remove(field);
                    }
                }
                let chain = f.chain(metadata, &[], None);
                if route != "ordinary" {
                    f.configure(&chain).await?;
                }
                if route == "cached" {
                    cache(&f.state, &chain).await?;
                }
                let acquisitions = AtomicUsize::new(0);
                let response = complete_upstream_authorize_with(
                    &f.state,
                    "https://local.example",
                    "connection",
                    &f.authorize_context(),
                    &authorize_input(&["openid"], None),
                    |_, _| {
                        acquisitions.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Ok(chain.clone()))
                    },
                )
                .await;
                check_authorize_result(&f, response, par != Some(true) && jar != Some(true))
                    .await?;
                assert_eq!(
                    acquisitions.load(Ordering::SeqCst),
                    usize::from(route == "fresh")
                );
            }
        }
        Ok(())
    })
}

#[test]
fn upstream_request_modes_policy_cannot_hide_or_introduce_incompatibility() -> ManagementTestResult
{
    run(async {
        for field in FLAGS {
            for replacement in [Value::Null, json!(false), json!(true)] {
                for cached in [false, true] {
                    let mut f = Fixture::new(1).await?;
                    let original_true = replacement != json!(true);
                    if field == FLAGS[0] {
                        f.discovery.require_pushed_authorization_requests = Some(original_true);
                    } else {
                        f.discovery.require_signed_request_object = Some(original_true);
                    }
                    f.reset_discovery()?;
                    let chain = f.chain(
                        f.metadata(),
                        &[Some(
                            json!({"openid_provider":{(field):{"value":replacement}}}),
                        )],
                        None,
                    );
                    f.configure(&chain).await?;
                    if cached {
                        cache(&f.state, &chain).await?;
                    }
                    let acquisitions = AtomicUsize::new(0);
                    let response = complete_upstream_authorize_with(
                        &f.state,
                        "https://local.example",
                        "connection",
                        &f.authorize_context(),
                        &authorize_input(&["openid"], None),
                        |_, _| {
                            acquisitions.fetch_add(1, Ordering::SeqCst);
                            std::future::ready(Ok(chain.clone()))
                        },
                    )
                    .await;
                    check_authorize_result(&f, response, false).await?;
                    assert_eq!(
                        acquisitions.load(Ordering::SeqCst),
                        usize::from(!original_true && !cached)
                    );
                }
            }
        }
        Ok(())
    })
}

#[test]
fn upstream_request_modes_resolved_shape_and_optional_deletion() -> ManagementTestResult {
    run(async {
        for field in FLAGS {
            for (value, allowed) in [
                (json!("true"), false),
                (json!(1), false),
                (json!([]), false),
                (json!({}), false),
                (Value::Null, true),
                (json!(false), true),
            ] {
                let f = Fixture::new(0).await?;
                let chain = f.chain(
                    f.metadata(),
                    &[Some(json!({"openid_provider":{(field):{"value":value}}}))],
                    None,
                );
                f.configure(&chain).await?;
                cache(&f.state, &chain).await?;
                let response = complete_upstream_authorize_with(
                    &f.state,
                    "https://local.example",
                    "connection",
                    &f.authorize_context(),
                    &authorize_input(&["openid"], None),
                    fail_acquisition,
                )
                .await;
                check_authorize_result(&f, response, allowed).await?;
            }
        }
        Ok(())
    })
}

#[test]
fn upstream_request_modes_true_do_not_block_issued_code_or_refresh() -> ManagementTestResult {
    run(async {
        for anchors in [false, true] {
            let mut f = Fixture::new(1).await?;
            f.discovery.require_pushed_authorization_requests = Some(true);
            f.discovery.require_signed_request_object = Some(true);
            f.reset_discovery()?;
            let chain = f.chain(f.metadata(), &[], None);
            if anchors {
                f.configure(&chain).await?;
                cache(&f.state, &chain).await?;
            }
            perform_upstream_callback_exchange_with(
                &f.state,
                &f.request,
                "code",
                "https://local.example",
                fail_acquisition,
            )
            .await
            .map_err(response_error)?;
            for id_token in [None, Some(jsonwebtoken::Algorithm::RS256)] {
                f.respond(id_token)?;
                let link = f.refresh_link();
                let exchange = perform_upstream_refresh_exchange_with(
                    &f.state,
                    "https://local.example",
                    &link,
                    &f.profile,
                    fail_acquisition,
                )
                .await
                .map_err(response_error)?;
                validate_upstream_refresh_exchange(
                    &f.state,
                    "https://local.example",
                    &link,
                    &exchange,
                )
                .await
                .map_err(response_error)?;
            }
            assert_eq!(f.calls.load(Ordering::SeqCst), 3);
            assert_eq!(f.state.upstream.auth_store.pending_count_for_tests()?, 0);
        }
        Ok(())
    })
}

#[test]
fn upstream_policy_removed_issuer_refuses_before_authorize_state_or_redirect(
) -> ManagementTestResult {
    run(async {
        for cached in [false, true] {
            let f = Fixture::new(1).await?;
            let chain = f.chain(
                f.metadata(),
                &[Some(json!({"openid_provider":{"issuer":{"value":null}}}))],
                None,
            );
            let original_jwts = chain.chain_jwts.clone();
            let resolved = chain.trust_chain.resolved_metadata()?.unwrap();
            assert!(!resolved["openid_provider"]
                .as_object()
                .unwrap()
                .contains_key("issuer"));
            f.configure(&chain).await?;
            if cached {
                cache(&f.state, &chain).await?;
            }
            let acquisitions = AtomicUsize::new(0);
            let response = complete_upstream_authorize_with(
                &f.state,
                "https://local.example",
                "connection",
                &f.authorize_context(),
                &authorize_input(&["openid"], None),
                |_, _| {
                    acquisitions.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(chain.clone()))
                },
            )
            .await;
            check_authorize_result(&f, response, false).await?;
            assert_eq!(acquisitions.load(Ordering::SeqCst), usize::from(!cached));
            assert_eq!(chain.chain_jwts, original_jwts);
        }
        Ok(())
    })
}
