use super::*;
use crate::web::upstream_authorize::{
    discovery::fetch_upstream_authorize_discovery_with,
    flow::{build_upstream_authorize_redirect_response, store_upstream_authorize_request},
};

#[test]
fn federation_effective_authorize_consumes_narrowing_and_captures_iss() -> ManagementTestResult {
    run(async {
        let f = Fixture::new(1).await?;
        let lower = json!({"openid_provider":{"scopes_supported":{"subset_of":["openid","email"]},"acr_values_supported":{"subset_of":["high"]}}});
        let upper = json!({"openid_provider":{"scopes_supported":{"subset_of":["openid"]}}});
        let chain = f.chain(f.metadata(), &[Some(lower), Some(upper)], None);
        f.configure(&chain).await?;
        let mut context = f.authorize_context();
        context.profile.require_iss_parameter = false;
        let input = authorize_input(&["openid"], Some("high"));
        let calls = AtomicUsize::new(0);
        let effective = fetch_upstream_authorize_discovery_with(
            &f.state,
            "https://local.example",
            &context,
            &input,
            |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(chain.clone()))
            },
        )
        .await
        .map_err(response_error)?;
        assert_eq!(effective.scopes_supported, Some(vec!["openid".into()]));
        let flow = store_upstream_authorize_request(
            &f.state,
            "connection",
            &input,
            &context,
            &effective,
            "https://local.example",
        )
        .await
        .map_err(response_error)?;
        let redirect = build_upstream_authorize_redirect_response(
            "https://local.example",
            &effective,
            "client",
            &input,
            &flow,
            false,
        )
        .map_err(response_error)?;
        let url = url::Url::parse(redirect.headers()["location"].to_str()?)?;
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["scope"], "openid");
        assert_eq!(params["acr_values"], "high");
        let captured = f
            .state
            .upstream
            .auth_store
            .try_consume_async(params["state"].clone())
            .await?
            .unwrap();
        assert!(captured.require_iss_parameter);
        assert_eq!(captured.token_endpoint, effective.token_endpoint);
        for rejected in [
            authorize_input(&["openid", "email"], Some("high")),
            authorize_input(&["openid"], Some("low")),
        ] {
            assert!(fetch_upstream_authorize_discovery_with(
                &f.state,
                "https://local.example",
                &context,
                &rejected,
                fail_acquisition
            )
            .await
            .is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            f.state
                .upstream
                .discovery_cache
                .try_get(ISSUER)?
                .unwrap()
                .scopes_supported,
            f.discovery.scopes_supported
        );
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
        Ok(())
    })
}

#[test]
fn federation_effective_optional_absence_empty_and_required_fields() -> ManagementTestResult {
    run(async {
        let f = Fixture::new(0).await?;
        let context = f.authorize_context();
        let input = authorize_input(&["openid"], None);
        for (policy, allowed) in [
            (json!({"scopes_supported":{"value":null}}), true),
            (json!({"scopes_supported":{"value":[]}}), false),
            (json!({"token_endpoint":{"value":null}}), false),
            (json!({"subject_types_supported":{"value":null}}), false),
            (
                json!({"response_types_supported":{"value":["CODE"]}}),
                false,
            ),
            (
                json!({"grant_types_supported":{"value":["AUTHORIZATION_CODE"]}}),
                false,
            ),
            (
                json!({"token_endpoint_auth_methods_supported":{"value":["CLIENT_SECRET_POST"]}}),
                false,
            ),
            (
                json!({"code_challenge_methods_supported":{"value":null}}),
                false,
            ),
            (
                json!({"authorization_response_iss_parameter_supported":{"value":null}}),
                false,
            ),
        ] {
            let chain = f.chain(
                f.metadata(),
                &[Some(json!({"openid_provider":policy}))],
                None,
            );
            f.configure(&chain).await?;
            f.reset_discovery()?;
            cache(&f.state, &chain).await?;
            let result = fetch_upstream_authorize_discovery_with(
                &f.state,
                "https://local.example",
                &context,
                &input,
                fail_acquisition,
            )
            .await;
            assert_eq!(result.is_ok(), allowed, "{policy}");
        }
        let mut basic = f.authorize_context();
        basic.auth_method = "client_secret_basic".into();
        basic.connection.client_auth_method = basic.auth_method.clone();
        basic.profile.token_endpoint_auth_methods_allowed = vec![basic.auth_method.clone()];
        let deleted = f.chain(
            f.metadata(),
            &[Some(
                json!({"openid_provider":{"token_endpoint_auth_methods_supported":{"value":null}}}),
            )],
            None,
        );
        f.reset_discovery()?;
        cache(&f.state, &deleted).await?;
        assert!(fetch_upstream_authorize_discovery_with(
            &f.state,
            "https://local.example",
            &basic,
            &input,
            fail_acquisition
        )
        .await
        .is_ok());
        assert!(fetch_upstream_authorize_discovery_with(
            &f.state,
            "https://local.example",
            &context,
            &input,
            fail_acquisition
        )
        .await
        .is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
        Ok(())
    })
}

#[test]
fn federation_effective_exact_identity_endpoints_overlay_and_no_downgrade() -> ManagementTestResult
{
    run(async {
        let f = Fixture::new(0).await?;
        let context = f.authorize_context();
        let input = authorize_input(&["openid"], None);
        // Only a genuinely empty anchor list uses ordinary Discovery.
        assert!(fetch_upstream_authorize_discovery_with(
            &f.state,
            "https://local.example",
            &context,
            &input,
            fail_acquisition
        )
        .await
        .is_ok());
        for (key, value) in [
            ("issuer", json!("https://upstream.example/")),
            ("issuer", json!(" https://upstream.example")),
            ("token_endpoint", json!("https://upstream.example/other")),
            ("jwks_uri", json!("https://upstream.example/other-keys")),
            ("end_session_endpoint", json!("http://10.0.0.1/logout")),
        ] {
            let mut metadata = f.metadata();
            metadata[key] = value;
            let chain = f.chain(metadata, &[], None);
            f.configure(&chain).await?;
            f.reset_discovery()?;
            cache(&f.state, &chain).await?;
            assert!(
                fetch_upstream_authorize_discovery_with(
                    &f.state,
                    "https://local.example",
                    &context,
                    &input,
                    fail_acquisition
                )
                .await
                .is_err(),
                "{key}"
            );
        }
        let mut raw = f.metadata();
        raw["token_endpoint"] = json!("https://upstream.example/old-token");
        let overlay = json!({"token_endpoint":f.discovery.token_endpoint});
        let chain = f.chain(raw, &[], Some(overlay));
        f.reset_discovery()?;
        cache(&f.state, &chain).await?;
        assert!(fetch_upstream_authorize_discovery_with(
            &f.state,
            "https://local.example",
            &context,
            &input,
            fail_acquisition
        )
        .await
        .is_ok());
        let bad = f.chain(f.metadata(), &[Some(json!({"unused":{"x":{}}}))], None);
        f.reset_discovery()?;
        cache(&f.state, &bad).await?;
        assert!(fetch_upstream_authorize_discovery_with(
            &f.state,
            "https://local.example",
            &context,
            &input,
            |_, _| std::future::ready(Err(FederationError::ChainResolution(
                "no trust anchors configured for this environment".into()
            )))
        )
        .await
        .is_err());
        let no_role = f.chain_without_op();
        f.reset_discovery()?;
        cache(&f.state, &no_role).await?;
        assert!(fetch_upstream_authorize_discovery_with(
            &f.state,
            "https://local.example",
            &context,
            &input,
            fail_acquisition
        )
        .await
        .is_err());
        // A missing required issuer is never filled from ordinary Discovery.
        let mut metadata = f.metadata();
        metadata.as_object_mut().unwrap().remove("issuer");
        let missing = f.chain(metadata, &[], None);
        f.reset_discovery()?;
        cache(&f.state, &missing).await?;
        assert!(fetch_upstream_authorize_discovery_with(
            &f.state,
            "https://local.example",
            &context,
            &input,
            fail_acquisition
        )
        .await
        .is_err());
        Ok(())
    })
}
