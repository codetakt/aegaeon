use super::*;
use crate::web::upstream_authorize::complete_upstream_authorize_with;
use crate::web::upstream_metadata::parse_upstream_discovery_body;

const FIELD: &str = "id_token_signing_alg_values_supported";
const CAPABILITY_ERROR: &str = "upstream OP signing capabilities must include RS256";
const OPERATIONS: [&str; 3] = ["authorize", "callback", "refresh"];

async fn exercise(
    f: &Fixture,
    operation: &str,
    chain: Option<&ResolvedTrustChain>,
    allowed: bool,
    expected_acquisitions: usize,
    algorithm: &str,
    expected_error: Option<&str>,
) -> ManagementTestResult {
    let acquisitions = AtomicUsize::new(0);
    let acquire = |_: Vec<TrustAnchor>, _: i64| {
        acquisitions.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(chain
            .expect("unexpected Federation acquisition")
            .clone()))
    };
    let rejection = match operation {
        "authorize" => {
            let mut context = f.authorize_context();
            context.issuer = f.request.issuer.clone();
            context.connection.issuer_url = f.request.issuer.clone();
            let response = complete_upstream_authorize_with(
                &f.state,
                "https://local.example",
                "connection",
                &context,
                &authorize_input(&["openid"], None),
                acquire,
            )
            .await;
            if allowed {
                assert_eq!(response.status(), StatusCode::FOUND);
                assert_eq!(f.state.upstream.auth_store.pending_count_for_tests()?, 1);
                let location = url::Url::parse(response.headers()["location"].to_str()?)?;
                let params: std::collections::HashMap<_, _> =
                    location.query_pairs().into_owned().collect();
                assert!(f
                    .state
                    .upstream
                    .auth_store
                    .try_consume_async(params["state"].clone())
                    .await?
                    .is_some());
                None
            } else {
                Some(response)
            }
        }
        "callback" => {
            match perform_upstream_callback_exchange_with(
                &f.state,
                &f.request,
                "code",
                "https://local.example",
                acquire,
            )
            .await
            {
                Ok(exchange) => {
                    assert!(allowed);
                    assert_eq!(exchange.id_token.signing_alg, algorithm);
                    None
                }
                Err(response) => Some(response),
            }
        }
        "refresh" => {
            let mut link = f.refresh_link();
            link.upstream_issuer = f.request.issuer.clone();
            match perform_upstream_refresh_exchange_with(
                &f.state,
                "https://local.example",
                &link,
                &f.profile,
                acquire,
            )
            .await
            {
                Ok(exchange) => {
                    assert!(allowed);
                    validate_upstream_refresh_exchange(
                        &f.state,
                        "https://local.example",
                        &link,
                        &exchange,
                    )
                    .await
                    .map_err(response_error)?;
                    None
                }
                Err(response) => Some(response),
            }
        }
        _ => panic!("unknown operation"),
    };
    assert_eq!(rejection.is_none(), allowed);
    if let Some(response) = rejection {
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(!response.headers().contains_key("location"));
        let body: Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body["error"], "server_error");
        if let Some(message) = expected_error {
            assert_eq!(body["error_description"], message);
        }
        let text = body.to_string();
        for secret in ["test-client-secret", "refresh-secret", "foreign-algorithm"] {
            assert!(!text.contains(secret));
        }
    }
    assert_eq!(acquisitions.load(Ordering::SeqCst), expected_acquisitions);
    let token_calls = usize::from(allowed && operation != "authorize");
    assert_eq!(f.calls.load(Ordering::SeqCst), token_calls);
    assert_eq!(f.forms.lock().unwrap().len(), token_calls);
    assert_eq!(f.state.upstream.auth_store.pending_count_for_tests()?, 0);
    Ok(())
}

#[test]
fn upstream_signing_capabilities_check_ordinary_cached_typed_metadata() -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for algorithms in [
                json!(["RS256"]),
                json!(["RS256", "RS384"]),
                json!(["RS256", "RS256", "extension", "none"]),
                json!([]),
                json!(["rs256"]),
                json!([" RS256"]),
                json!(["RS256 "]),
                json!(["foreign-algorithm"]),
                json!(["RS384"]),
                json!(["none"]),
            ] {
                let mut f = Fixture::new(0).await?;
                f.discovery.id_token_signing_alg_values_supported =
                    serde_json::from_value(algorithms.clone())?;
                f.reset_discovery()?;
                let allowed = algorithms.as_array().unwrap().contains(&json!("RS256"));
                let algorithm = if algorithms.as_array().unwrap().contains(&json!("RS384")) {
                    f.respond(Some(jsonwebtoken::Algorithm::RS384))?;
                    "RS384"
                } else {
                    "RS256"
                };
                exercise(
                    &f,
                    operation,
                    None,
                    allowed,
                    0,
                    algorithm,
                    (!allowed).then_some(CAPABILITY_ERROR),
                )
                .await?;
            }
        }
        Ok(())
    })
}

#[test]
fn upstream_signing_capabilities_raw_discovery_refuses_before_side_effects() -> ManagementTestResult
{
    run(async {
        for operation in OPERATIONS {
            for value in [
                None,
                Some(Value::Null),
                Some(json!("RS256")),
                Some(json!(true)),
                Some(json!(42)),
                Some(json!({})),
                Some(json!(["RS256", false])),
                Some(json!([])),
                Some(json!(["rs256"])),
                Some(json!([" RS256"])),
                Some(json!(["foreign-algorithm"])),
                Some(json!(["RS384"])),
            ] {
                let mut f = Fixture::new(0).await?;
                let mut raw = f.metadata();
                match value {
                    Some(value) => {
                        raw[FIELD] = value;
                    }
                    None => {
                        raw.as_object_mut().unwrap().remove(FIELD);
                    }
                }
                let parses = parse_upstream_discovery_body(&serde_json::to_vec(&raw)?).is_ok();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                // Existing test-only loopback transport reaches the production
                // raw parser. Failure occurs before issuer matching or token use.
                f.request.issuer = format!("http://{}", listener.local_addr()?);
                let app = Router::new().fallback(axum::routing::get(move || {
                    let body = raw.clone();
                    async move { Json(body) }
                }));
                let task = tokio::spawn(async move {
                    axum::serve(listener, app).await.unwrap();
                });
                exercise(
                    &f,
                    operation,
                    None,
                    false,
                    0,
                    "RS256",
                    Some(if parses {
                        CAPABILITY_ERROR
                    } else {
                        "upstream discovery response invalid"
                    }),
                )
                .await?;
                task.abort();
            }
        }
        Ok(())
    })
}

#[test]
fn upstream_signing_capabilities_check_signed_raw_and_retained_fields() -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for cached in [false, true] {
                for value in [
                    None,
                    Some(Value::Null),
                    Some(json!("RS256")),
                    Some(json!(true)),
                    Some(json!(12)),
                    Some(json!({})),
                    Some(json!(["RS256", null])),
                    Some(json!([])),
                    Some(json!(["rs256"])),
                    Some(json!(["RS256 "])),
                    Some(json!(["foreign-algorithm"])),
                    Some(json!(["RS384"])),
                    Some(json!(["RS256"])),
                    Some(json!(["RS256", "RS384"])),
                ] {
                    let f = Fixture::new(1).await?;
                    let mut metadata = f.metadata();
                    let allowed = value
                        .as_ref()
                        .is_some_and(|v| v == &json!(["RS256"]) || v == &json!(["RS256", "RS384"]));
                    let invalid_original = value.as_ref() == Some(&Value::Null);
                    match value {
                        Some(value) => {
                            metadata[FIELD] = value;
                        }
                        None => {
                            metadata.as_object_mut().unwrap().remove(FIELD);
                        }
                    }
                    let chain = f.chain(metadata, &[], None);
                    let originals = chain.chain_jwts.clone();
                    f.configure(&chain).await?;
                    if cached {
                        cache(&f.state, &chain).await?;
                    }
                    exercise(
                        &f,
                        operation,
                        Some(&chain),
                        allowed,
                        usize::from(!cached || invalid_original),
                        "RS256",
                        None,
                    )
                    .await?;
                    assert_eq!(chain.chain_jwts, originals);
                }
            }
        }
        Ok(())
    })
}

#[test]
fn upstream_signing_capabilities_policies_and_superior_completion_preserve_partial_inputs(
) -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for cached in [false, true] {
                for source in ["value", "default", "subset_of", "superior"] {
                    for list in [
                        json!(["RS256"]),
                        json!(["RS256", "RS384"]),
                        json!(["RS384"]),
                        json!([]),
                    ] {
                        let f = Fixture::new(1).await?;
                        let mut metadata = f.metadata();
                        metadata[FIELD] = json!(["RS384"]);
                        if source == "default" || source == "superior" {
                            metadata.as_object_mut().unwrap().remove(FIELD);
                        } else if source == "subset_of" {
                            metadata[FIELD] = json!(["RS256", "RS384", "RS512"]);
                        }
                        let policies = if source == "superior" {
                            vec![]
                        } else {
                            vec![
                                None,
                                Some(json!({"openid_provider":{(FIELD):{(source):list}}})),
                            ]
                        };
                        let chain = f.chain(
                            metadata,
                            &policies,
                            (source == "superior").then(|| json!({(FIELD):list})),
                        );
                        let originals = chain.chain_jwts.clone();
                        f.configure(&chain).await?;
                        if cached {
                            cache(&f.state, &chain).await?;
                        }
                        let allowed = list.as_array().unwrap().contains(&json!("RS256"));
                        let algorithm = if list.as_array().unwrap().contains(&json!("RS384")) {
                            f.respond(Some(jsonwebtoken::Algorithm::RS384))?;
                            "RS384"
                        } else {
                            "RS256"
                        };
                        exercise(
                            &f,
                            operation,
                            Some(&chain),
                            allowed,
                            usize::from(!cached),
                            algorithm,
                            (!allowed).then_some(CAPABILITY_ERROR),
                        )
                        .await?;
                        assert_eq!(chain.chain_jwts, originals);
                    }
                }
                for value in [
                    Value::Null,
                    json!("RS256"),
                    json!(true),
                    json!(["RS256", 42]),
                ] {
                    let f = Fixture::new(0).await?;
                    let chain = f.chain(
                        f.metadata(),
                        &[Some(json!({"openid_provider":{(FIELD):{"value":value}}}))],
                        None,
                    );
                    f.configure(&chain).await?;
                    if cached {
                        cache(&f.state, &chain).await?;
                    }
                    exercise(
                        &f,
                        operation,
                        Some(&chain),
                        false,
                        usize::from(!cached),
                        "RS256",
                        Some("resolved federation OP metadata invalid"),
                    )
                    .await?;
                }
                let f = Fixture::new(0).await?;
                let chain = f.chain(json!({}), &[], Some(f.metadata()));
                f.configure(&chain).await?;
                if cached {
                    cache(&f.state, &chain).await?;
                }
                exercise(
                    &f,
                    operation,
                    Some(&chain),
                    true,
                    usize::from(!cached),
                    "RS256",
                    None,
                )
                .await?;
            }
        }
        Ok(())
    })
}

#[test]
fn upstream_signing_capabilities_signed_result_replaces_ordinary_capabilities(
) -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for cached in [false, true] {
                for algorithms in [json!(["RS256"]), json!(["RS256", "RS384"])] {
                    let mut f = Fixture::new(0).await?;
                    let mut metadata = f.metadata();
                    metadata[FIELD] = algorithms.clone();
                    let chain = f.chain(metadata, &[], None);
                    f.configure(&chain).await?;
                    if cached {
                        cache(&f.state, &chain).await?;
                    }
                    f.discovery.id_token_signing_alg_values_supported = vec!["RS384".into()];
                    f.reset_discovery()?;
                    let algorithm = if algorithms.as_array().unwrap().contains(&json!("RS384")) {
                        f.respond(Some(jsonwebtoken::Algorithm::RS384))?;
                        "RS384"
                    } else {
                        "RS256"
                    };
                    exercise(
                        &f,
                        operation,
                        Some(&chain),
                        true,
                        usize::from(!cached),
                        algorithm,
                        None,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    })
}
