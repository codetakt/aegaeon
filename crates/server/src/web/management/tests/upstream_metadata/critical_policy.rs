use super::*;
use crate::web::upstream_authorize::discovery::fetch_upstream_authorize_discovery_with;

#[test]
fn federation_critical_policy_changes_effective_operations_and_refuses_unknown_before_credentials(
) -> ManagementTestResult {
    run(async {
        for intermediates in [0, 2] {
            let f = Fixture::new(intermediates).await?;
            let policy = json!({"openid_provider":{"scopes_supported":{"intersect":["openid"]},"id_token_signing_alg_values_supported":{"intersect":["RS256"]}}});
            let mut permitted = f.chain(f.metadata(), &[Some(policy)], None);
            f.set_critical_policy(&mut permitted, intermediates, &["intersect", "intersect"]);
            f.configure(&permitted).await?;
            let context = f.authorize_context();
            let input = authorize_input(&["openid"], Some("high"));
            let effective = fetch_upstream_authorize_discovery_with(
                &f.state,
                "https://local.example",
                &context,
                &input,
                |_, _| std::future::ready(Ok(permitted.clone())),
            )
            .await
            .map_err(response_error)?;
            assert_eq!(effective.scopes_supported, Some(vec!["openid".into()]));
            assert_eq!(
                effective.id_token_signing_alg_values_supported,
                vec!["RS256".to_owned()]
            );
            assert!(fetch_upstream_authorize_discovery_with(
                &f.state,
                "https://local.example",
                &context,
                &authorize_input(&["openid", "email"], Some("high")),
                fail_acquisition,
            )
            .await
            .is_err());
            assert_eq!(f.calls.load(Ordering::SeqCst), 0);
            perform_upstream_callback_exchange_with(
                &f.state,
                &f.request,
                "code",
                "https://local.example",
                fail_acquisition,
            )
            .await
            .map_err(response_error)?;
            f.respond(None)?;
            let link = f.refresh_link();
            let refresh = perform_upstream_refresh_exchange_with(
                &f.state,
                "https://local.example",
                &link,
                &f.profile,
                fail_acquisition,
            )
            .await
            .map_err(response_error)?;
            assert!(refresh.token_response.id_token.is_none());
            validate_upstream_refresh_exchange(&f.state, "https://local.example", &link, &refresh)
                .await
                .map_err(response_error)?;
            assert_eq!(f.calls.load(Ordering::SeqCst), 2);
            let mut rejected = permitted.clone();
            f.set_critical_policy(&mut rejected, intermediates, &["unsupported"]);
            // Cache and fresh acquisition both contain the unsupported signed list.
            // A valid ordinary Discovery cache cannot restore acceptance.
            cache(&f.state, &rejected).await?;
            f.reset_discovery()?;
            assert!(fetch_upstream_authorize_discovery_with(
                &f.state,
                "https://local.example",
                &context,
                &input,
                |_, _| std::future::ready(Ok(rejected.clone())),
            )
            .await
            .is_err());
            f.reset_discovery()?;
            assert!(perform_upstream_callback_exchange_with(
                &f.state,
                &f.request,
                "code",
                "https://local.example",
                |_, _| std::future::ready(Ok(rejected.clone())),
            )
            .await
            .is_err());
            f.reset_discovery()?;
            assert!(perform_upstream_refresh_exchange_with(
                &f.state,
                "https://local.example",
                &link,
                &f.profile,
                |_, _| std::future::ready(Ok(rejected.clone())),
            )
            .await
            .is_err());
            assert_eq!(f.calls.load(Ordering::SeqCst), 2);
        }
        Ok(())
    })
}
