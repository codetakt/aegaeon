use super::*;
use crate::web::upstream_authorize::discovery::fetch_upstream_authorize_discovery_with;

#[test]
fn federation_entity_type_filter_controls_live_operations_before_credentials(
) -> ManagementTestResult {
    run(async {
        for intermediates in [0, 2] {
            let f = Fixture::new(intermediates).await?;
            let mut permitted = f.chain(f.metadata(), &[], None);
            f.set_allowed_entity_types(&mut permitted, intermediates, &["openid_provider"]);
            f.configure(&permitted).await?;
            let context = f.authorize_context();
            let input = authorize_input(&["openid"], Some("high"));
            fetch_upstream_authorize_discovery_with(
                &f.state,
                "https://local.example",
                &context,
                &input,
                |_, _| std::future::ready(Ok(permitted.clone())),
            )
            .await
            .map_err(response_error)?;
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
            for allowed in [vec![], vec!["OPENID_PROVIDER"]] {
                let mut excluded = permitted.clone();
                f.set_allowed_entity_types(&mut excluded, intermediates, &allowed);
                cache(&f.state, &excluded).await?;
                assert!(fetch_upstream_authorize_discovery_with(
                    &f.state,
                    "https://local.example",
                    &context,
                    &input,
                    fail_acquisition,
                )
                .await
                .is_err());
                f.reset_discovery()?;
                assert!(perform_upstream_callback_exchange_with(
                    &f.state,
                    &f.request,
                    "code",
                    "https://local.example",
                    fail_acquisition,
                )
                .await
                .is_err());
                f.reset_discovery()?;
                assert!(perform_upstream_refresh_exchange_with(
                    &f.state,
                    "https://local.example",
                    &link,
                    &f.profile,
                    fail_acquisition,
                )
                .await
                .is_err());
                f.reset_discovery()?;
                assert_eq!(f.calls.load(Ordering::SeqCst), 2);
            }
        }
        Ok(())
    })
}
