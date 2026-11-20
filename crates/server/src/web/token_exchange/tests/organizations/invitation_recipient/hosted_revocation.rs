use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_hosted_invitation_closes_family_root_and_child() -> TestResult {
    let mut f = setup::new().await?;
    setup::lifetime(&mut f.state, 900).await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(
        &witness,
        Box::pin(async {
            let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
            let concurrent_key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
            let deadline = std::time::SystemTime::now() + std::time::Duration::from_secs(600);
            let (parent, child) = setup::token_with_deadline(&f, &key, Some(deadline)).await?;
            let (_, concurrent) =
                setup::token_with_deadline(&f, &concurrent_key, Some(deadline)).await?;
            let source = parent["access_token"].as_str().ok_or("source token")?;
            let refresh = parent["refresh_token"].as_str().ok_or("family token")?;
            let parent_ttl = parent["expires_in"].as_u64().ok_or("parent lifetime")?;
            assert!((301..=600).contains(&parent_ttl));
            let child_record = f
                .state
                .tokens
                .store
                .try_verify_access_token_async(child.clone())
                .await?
                .ok_or("recipient token")?;
            assert!((1..=300).contains(&child_record.expires_in));
            let status = f.path("challenge-status");
            let body = json!({"invitationCapability":f.capability});
            let proof = f.proof(&key, &child, &status)?;
            assert_eq!(
                f.post(&status, &child, Some(&proof), &body).await?.0,
                StatusCode::OK
            );
            // Simulate losing the first acknowledgement. The cleanup-only handle
            // repeats precisely the same authenticated revocation.
            for _ in 0..2 {
                let (code, response) = http(
                    &f.state,
                    "/revoke",
                    OWNER,
                    &[("token", refresh), ("token_type_hint", "refresh_token")],
                    None,
                    false,
                )
                .await?;
                assert_eq!(code, StatusCode::OK);
                assert!(response.is_null());
            }
            let signed = crate::web::test_support::native_dpop::proof(&f.state, &key, json!({}))?;
            let (code, response) = http(
                &f.state,
                "/token",
                OWNER,
                &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
                Some(&signed),
                false,
            )
            .await?;
            assert_eq!(code, StatusCode::BAD_REQUEST);
            assert_eq!(response["error"], "invalid_grant");
            let signed = crate::web::test_support::native_dpop::proof(&f.state, &key, json!({}))?;
            let (code, response) = http(
                &f.state,
                "/token",
                OWNER,
                &[
                    ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
                    ("subject_token", source),
                    (
                        "subject_token_type",
                        "urn:ietf:params:oauth:token-type:access_token",
                    ),
                    (
                        "audience",
                        &format!("{}/organization-invitations", f.state.issuer),
                    ),
                    ("scope", SCOPE),
                ],
                Some(&signed),
                false,
            )
            .await?;
            assert_eq!(code, StatusCode::BAD_REQUEST);
            assert!(response.get("access_token").is_none());
            let signed = f.proof(&key, &child, &status)?;
            assert_eq!(
                f.post(&status, &child, Some(&signed), &body).await?.0,
                StatusCode::UNAUTHORIZED
            );
            let signed = f.proof(&concurrent_key, &concurrent, &status)?;
            assert_eq!(
                f.post(&status, &concurrent, Some(&signed), &body).await?.0,
                StatusCode::OK
            );
            Ok(())
        }),
    )
    .await;
    drop(witness);
    f.finish(result).await
}
