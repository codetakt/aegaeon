use super::*;

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn jwk_binding_pg_callback_exact_names_complete_session_and_aliases_refuse() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let flow = Flow::new(f).await?;
            let claims = f.claims()?;
            let token = flow.signed(&claims)?;
            flow.token(token);
            let response = flow.callback().await?;
            assert_eq!(response.status(), StatusCode::FOUND);
            assert!(response.headers().contains_key(header::SET_COOKIE));
            assert_eq!(flow.keys.hits(), 1);
            let stored = f.stored().await?;
            flow.assert_no_effects(f, &stored, 1).await?;
            // Only metadata changes; the HTTP token endpoint returns identical signed bytes.
            for declared in ["rs256", "Rs256", " RS256", "RS256 ", "PS256", ""] {
                let mut keys = serde_json::to_value(flow.new_key.jwks())?;
                keys["keys"][0]["alg"] = json!(declared);
                flow.cache_keys(keys)?;
                assert_eq!(flow.callback().await?.status(), StatusCode::BAD_GATEWAY);
                flow.assert_no_effects(f, &stored, 1).await?;
            }
            flow.cache_keys(serde_json::to_value(flow.new_key.jwks())?)?;
            for declared in ["rs256", "Rs256", " RS256", "RS256 ", "PS256", ""] {
                let mut discovery = flow.discovery.clone();
                discovery.id_token_signing_alg_values_supported = vec![declared.into()];
                flow.state
                    .upstream
                    .discovery_cache
                    .try_insert(&flow.request.issuer, discovery)?;
                assert_eq!(flow.callback().await?.status(), StatusCode::BAD_GATEWAY);
                flow.assert_no_effects(f, &stored, 1).await?;
            }
            flow.state
                .upstream
                .discovery_cache
                .try_insert(&flow.request.issuer, flow.discovery.clone())?;
            let mut keys = serde_json::to_value(flow.new_key.jwks())?;
            keys["keys"][0].as_object_mut().ok_or("key")?.remove("alg");
            flow.cache_keys(keys)?;
            assert_eq!(flow.callback().await?.status(), StatusCode::FOUND);
            assert_eq!(
                flow.state
                    .browser_auth
                    .auth_sessions
                    .try_list_for_user(&f.user)?
                    .len(),
                2
            );
            assert_eq!(
                flow.keys.hits(),
                1,
                "known keys use cache despite refused metadata"
            );
            assert_eq!(flow.tokens.hits(), 14);
            Ok(())
        })
    })
}
