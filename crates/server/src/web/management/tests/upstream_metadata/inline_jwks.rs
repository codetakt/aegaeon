use super::*;

#[derive(Clone, Copy, Debug)]
enum Operation {
    Authorize,
    Callback,
    Refresh,
}

async fn operate(
    f: &Fixture,
    chain: &ResolvedTrustChain,
    cached: bool,
    operation: Operation,
) -> Result<(), axum::response::Response> {
    let acquire = |_, _| {
        assert!(!cached, "cached signed chain should be used");
        std::future::ready(Ok(chain.clone()))
    };
    match operation {
        Operation::Authorize => {
            crate::web::upstream_authorize::discovery::fetch_upstream_authorize_discovery_with(
                &f.state,
                "https://local.example",
                &f.authorize_context(),
                &authorize_input(&["openid"], Some("high")),
                acquire,
            )
            .await?;
        }
        Operation::Callback => {
            perform_upstream_callback_exchange_with(
                &f.state,
                &f.request,
                "code",
                "https://local.example",
                acquire,
            )
            .await?;
        }
        Operation::Refresh => {
            let link = f.refresh_link();
            let exchange = perform_upstream_refresh_exchange_with(
                &f.state,
                "https://local.example",
                &link,
                &f.profile,
                acquire,
            )
            .await?;
            assert!(exchange.token_response.id_token.is_none());
            validate_upstream_refresh_exchange(&f.state, "https://local.example", &link, &exchange)
                .await?;
        }
    }
    Ok(())
}

async fn check_inline_admission(operation: Operation) -> ManagementTestResult {
    for cached in [false, true] {
        let f = Fixture::new(1).await?;
        if matches!(operation, Operation::Refresh) {
            f.respond(None)?;
        }
        let key = f.jwks["keys"][0].clone();
        let mut encryption_key = key.clone();
        encryption_key["use"] = json!("enc");
        let mut no_verification = key.clone();
        no_verification["key_ops"] = json!(["encrypt"]);
        let mut wrong_member_type = key.clone();
        wrong_member_type["n"] = json!(42);
        let mut bad_encoding = key.clone();
        bad_encoding["n"] = json!("%%%invalid");
        let mut empty_component = key.clone();
        empty_component["e"] = json!("");
        for inline in [
            json!("invalid"),
            json!({}),
            json!({"keys":null}),
            json!({"keys":[{}]}),
            json!({"keys":[wrong_member_type]}),
            json!({"keys":[bad_encoding]}),
            json!({"keys":[empty_component]}),
            json!({"keys":[key.clone(), key.clone()]}),
            json!({"keys":[]}),
            json!({"keys":[encryption_key]}),
            json!({"keys":[no_verification]}),
        ] {
            let mut metadata = f.metadata();
            metadata["jwks"] = inline.clone();
            let chain = f.chain(metadata, &[], None);
            f.configure(&chain).await?;
            f.reset_discovery()?;
            if cached {
                cache(&f.state, &chain).await?;
            } else {
                // Fresh acquisition must not reuse the preceding invalid chain.
                f.state
                    .federation
                    .chain_cache
                    .cleanup_expired(i64::MAX)
                    .await?;
            }
            let response = operate(&f, &chain, cached, operation)
                .await
                .expect_err("malformed inline signing keys accepted");
            assert_eq!(response.status(), axum::http::StatusCode::BAD_GATEWAY);
            let body = axum::body::to_bytes(response.into_body(), 65536).await?;
            assert!(
                String::from_utf8(body.to_vec())?
                    .contains("federation openid_provider jwks invalid"),
                "{operation:?} cached={cached} inline={inline}"
            );
            assert_eq!(f.calls.load(Ordering::SeqCst), 0, "credentials sent");
            assert!(f.forms.lock().unwrap().is_empty());
        }
        // Missing/null constraints remain optional, and a valid constraint
        // permits the same operation. Refresh deliberately has no ID Token.
        for inline in [None, Some(Value::Null), Some(f.jwks.clone())] {
            let delete_by_policy = inline.as_ref().is_some_and(Value::is_null);
            let mut metadata = f.metadata();
            if let Some(inline) = inline {
                if !inline.is_null() {
                    metadata["jwks"] = inline;
                }
            } else {
                metadata.as_object_mut().unwrap().remove("jwks");
            }
            let policies = if delete_by_policy {
                vec![Some(json!({"openid_provider":{"jwks":{"value":null}}}))]
            } else {
                vec![]
            };
            let chain = f.chain(metadata, &policies, None);
            f.reset_discovery()?;
            cache(&f.state, &chain).await?;
            operate(&f, &chain, true, operation)
                .await
                .map_err(response_error)?;
        }
        assert_eq!(
            f.calls.load(Ordering::SeqCst),
            if matches!(operation, Operation::Authorize) {
                0
            } else {
                3
            }
        );
    }
    Ok(())
}

#[test]
fn federation_inline_jwks_authorize_rejects_before_redirect() -> ManagementTestResult {
    run(check_inline_admission(Operation::Authorize))
}

#[test]
fn federation_inline_jwks_callback_rejects_before_credentials() -> ManagementTestResult {
    run(check_inline_admission(Operation::Callback))
}

#[test]
fn federation_inline_jwks_refresh_without_id_token_rejects_before_credentials(
) -> ManagementTestResult {
    run(check_inline_admission(Operation::Refresh))
}
