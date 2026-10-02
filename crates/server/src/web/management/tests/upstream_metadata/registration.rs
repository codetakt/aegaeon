use super::signing_capabilities::exercise;
use super::*;
use crate::web::upstream_metadata::parse_upstream_discovery_body;

const MODES: &str = "client_registration_types_supported";
const ENDPOINT: &str = "federation_registration_endpoint";
const URL: &str = "https://Registration.example:8443/register?mode=explicit";
const ERROR: &str = "resolved federation OP registration declarations invalid";
const OPERATIONS: [&str; 3] = ["authorize", "callback", "refresh"];

#[test]
fn federation_registration_selected_operations_require_only_exact_explicit_endpoint(
) -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for cached in [false, true] {
                for (modes, endpoint, allowed) in [
                    (None, None, true),
                    (Some(json!([])), None, true),
                    (Some(json!(["automatic"])), None, true),
                    (
                        Some(json!(["EXPLICIT", "explicit ", " explicit", "future"])),
                        None,
                        true,
                    ),
                    (Some(json!(["explicit"])), None, false),
                    (
                        Some(json!(["automatic", "explicit", "explicit", "future"])),
                        Some(URL),
                        true,
                    ),
                ] {
                    let f = Fixture::new(1).await?;
                    let mut metadata = f.metadata();
                    if let Some(modes) = modes {
                        metadata[MODES] = modes;
                    }
                    if let Some(endpoint) = endpoint {
                        metadata[ENDPOINT] = json!(endpoint);
                    }
                    let chain = f.chain(metadata, &[], None);
                    let original = chain.chain_jwts.clone();
                    f.configure(&chain).await?;
                    if cached {
                        cache(&f.state, &chain).await?;
                    }
                    exercise(
                        &f,
                        operation,
                        Some(&chain),
                        allowed,
                        usize::from(!cached),
                        "RS256",
                        (!allowed).then_some(ERROR),
                    )
                    .await?;
                    assert_eq!(chain.chain_jwts, original);
                }
                // A generic HTTP declaration is not a registration request: if
                // it were invoked, this token server's call count would change.
                let f = Fixture::new(0).await?;
                let mut metadata = f.metadata();
                metadata[ENDPOINT] = json!(f.discovery.token_endpoint);
                metadata[MODES] = json!(["automatic", "future"]);
                let chain = f.chain(metadata, &[], None);
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
fn federation_registration_operations_allow_partial_superior_and_policy_completion(
) -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for cached in [false, true] {
                for source in ["superior", "value", "default", "empty-original"] {
                    let f = Fixture::new(1).await?;
                    let mut metadata = f.metadata();
                    metadata[MODES] = json!(["explicit"]);
                    let mut overlay = None;
                    let mut policies = vec![None, None];
                    match source {
                        "superior" => overlay = Some(json!({(ENDPOINT):URL})),
                        "empty-original" => {
                            metadata[ENDPOINT] = json!(URL);
                            overlay = Some(metadata);
                            metadata = json!({});
                        }
                        _ => {
                            policies[1] =
                                Some(json!({"openid_provider":{(ENDPOINT):{(source):URL}}}))
                        }
                    }
                    let chain = f.chain(metadata, &policies, overlay);
                    let original = chain.chain_jwts.clone();
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
                    assert_eq!(chain.chain_jwts, original);
                }
            }
        }
        Ok(())
    })
}

#[test]
fn federation_registration_operations_reject_invalid_originals_and_policy_results(
) -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            for cached in [false, true] {
                for case in [
                    "original-modes",
                    "original-url-repaired",
                    "endpoint-removed",
                    "derived-explicit",
                    "invalid-replacement",
                    "remove-mode",
                    "replace-mode",
                    "narrow-mode",
                ] {
                    let mut f = Fixture::new(1).await?;
                    // Independent Discovery has registration endpoint information;
                    // it cannot refill the removed signed value.
                    let mut ordinary = f.metadata();
                    ordinary[ENDPOINT] = json!(URL);
                    ordinary["registration_endpoint"] = json!(URL);
                    f.discovery = parse_upstream_discovery_body(&serde_json::to_vec(&ordinary)?)?;
                    f.reset_discovery()?;
                    let mut metadata = f.metadata();
                    metadata[MODES] = json!(["automatic", "explicit"]);
                    metadata[ENDPOINT] = json!(URL);
                    let mut overlay = None;
                    let policy = match case {
                        "original-modes" => {
                            metadata[MODES] = json!(["explicit", false]);
                            json!({(MODES):{"value":["explicit"]}})
                        }
                        "original-url-repaired" => {
                            metadata[ENDPOINT] = json!("relative/path");
                            overlay = Some(json!({(ENDPOINT):URL}));
                            json!({})
                        }
                        "derived-explicit" => {
                            metadata[MODES] = json!(["automatic"]);
                            json!({(MODES):{"value":["explicit"]}, (ENDPOINT):{"value":null}})
                        }
                        "invalid-replacement" => {
                            json!({(ENDPOINT):{"value":"http://unused.example/register"}})
                        }
                        "remove-mode" => json!({(MODES):{"value":null}, (ENDPOINT):{"value":null}}),
                        "replace-mode" => {
                            json!({(MODES):{"value":["EXPLICIT"]}, (ENDPOINT):{"value":null}})
                        }
                        "narrow-mode" => {
                            json!({(MODES):{"subset_of":["automatic"]}, (ENDPOINT):{"value":null}})
                        }
                        _ => json!({(ENDPOINT):{"value":null}}),
                    };
                    let policy = (!policy.as_object().expect("policy object").is_empty())
                        .then(|| json!({"openid_provider":policy}));
                    let chain = f.chain(metadata, &[None, policy], overlay);
                    let original = chain.chain_jwts.clone();
                    f.configure(&chain).await?;
                    if cached {
                        cache(&f.state, &chain).await?;
                    }
                    let allowed = matches!(case, "remove-mode" | "replace-mode" | "narrow-mode");
                    let partial_valid =
                        allowed || matches!(case, "endpoint-removed" | "derived-explicit");
                    exercise(
                        &f,
                        operation,
                        Some(&chain),
                        allowed,
                        usize::from(!cached || !partial_valid),
                        "RS256",
                        if allowed {
                            None
                        } else if partial_valid {
                            Some(ERROR)
                        } else {
                            Some("federation trust chain verification failed")
                        },
                    )
                    .await?;
                    assert_eq!(chain.chain_jwts, original);
                }
            }
        }
        Ok(())
    })
}

#[test]
fn federation_registration_ordinary_selection_remains_unchanged() -> ManagementTestResult {
    run(async {
        for operation in OPERATIONS {
            let mut f = Fixture::new(0).await?;
            let mut ordinary = f.metadata();
            ordinary[MODES] = json!(["explicit"]);
            ordinary[ENDPOINT] = json!("not a URL");
            f.discovery = parse_upstream_discovery_body(&serde_json::to_vec(&ordinary)?)?;
            f.reset_discovery()?;
            exercise(&f, operation, None, true, 0, "RS256", None).await?;
        }
        Ok(())
    })
}

#[test]
fn federation_registration_token_exchange_retains_one_selected_context() -> ManagementTestResult {
    run(async {
        for operation in ["callback", "refresh"] {
            let f = Fixture::new(1).await?;
            let mut metadata = f.metadata();
            metadata[MODES] = json!(["explicit"]);
            metadata[ENDPOINT] = json!(URL);
            let valid = f.chain(metadata.clone(), &[], None);
            let successor = f.chain(
                metadata,
                &[Some(json!({"openid_provider":{(ENDPOINT):{"value":null}}}))],
                None,
            );
            f.configure(&valid).await?;
            f.mutate_during_exchange(successor);
            exercise(&f, operation, Some(&valid), true, 1, "RS256", None).await?;
            let response = if operation == "callback" {
                perform_upstream_callback_exchange_with(
                    &f.state,
                    &f.request,
                    "code",
                    "https://local.example",
                    fail_acquisition,
                )
                .await
                .err()
                .expect("next operation must reject missing endpoint")
            } else {
                perform_upstream_refresh_exchange_with(
                    &f.state,
                    "https://local.example",
                    &f.refresh_link(),
                    &f.profile,
                    fail_acquisition,
                )
                .await
                .err()
                .expect("next operation must reject missing endpoint")
            };
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            let body: Value =
                serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
            assert_eq!(body["error_description"], ERROR);
            assert_eq!(f.calls.load(Ordering::SeqCst), 1);
            assert_eq!(f.forms.lock().unwrap().len(), 1);
            assert_eq!(f.state.upstream.auth_store.pending_count_for_tests()?, 0);
        }
        Ok(())
    })
}
