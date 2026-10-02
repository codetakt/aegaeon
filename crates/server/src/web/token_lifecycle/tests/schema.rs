use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn introspection_scope_presence_and_sender_type_match_stored_tokens() -> TestResult {
    let fixture = Fixture::new(true).await?;
    let state = &fixture.state;
    let result = async {
        for scope in [None, Some("read write"), Some("")] {
            for binding in [
                None,
                Some(SenderBinding::DPoP {
                    jkt: "public-fixture-jkt".into(),
                }),
                Some(SenderBinding::Mtls {
                    fingerprint: "ab".repeat(32),
                }),
            ] {
                let (mut access, refresh, mut meta) = grant(state, false, binding);
                access.scope = scope.map(str::to_string);
                meta.granted_scopes = scope
                    .unwrap_or_default()
                    .split_whitespace()
                    .map(str::to_string)
                    .collect();
                state
                    .tokens
                    .store
                    .store_issued_grant(access.clone(), refresh, meta)?;
                for jwt in [false, true] {
                    let (status, body) = introspection(state, &access.token, OWNER, jwt).await?;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(body["active"], true);
                    assert_eq!(body.get("scope"), scope.map(Value::from).as_ref());
                    assert_eq!(body["token_type"], access.token_type);
                    assert_eq!(body["sub"], access.user_id);
                    assert_eq!(body["iss"], state.issuer.as_str());
                    match access.cnf.as_ref() {
                        Some(CnfClaim::Jkt(jkt)) => assert_eq!(body["cnf"], json!({"jkt":jkt})),
                        Some(CnfClaim::X5tS256(thumbprint)) => {
                            assert_eq!(body["cnf"], json!({"x5t#S256":thumbprint}))
                        }
                        None => assert!(body.get("cnf").is_none()),
                    }
                    let (status, body) = introspection(state, &access.token, OTHER, jwt).await?;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(body, json!({"active":false}));
                }
            }
        }
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
