use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn shared_redis_refresh_parent_introspection_tracks_regular_grant_rotation() -> TestResult {
    for retain in [true, false] {
        let fixture = Fixture::new(retain).await?;
        let state = &fixture.state;
        let result = async {
            let (a1, r1, m1) = grant(state, true, None);
            let r1 = r1.ok_or("refresh missing")?;
            state
                .tokens
                .store
                .store_issued_grant(a1.clone(), Some(r1.clone()), m1)?;
            let r1 = state
                .tokens
                .store
                .try_get_refresh_token(&r1.token)?
                .ok_or("stored refresh missing")?;
            observe(state, &a1.token, true).await?;
            let mut prepared = r1.clone();
            let r2 = prepared.rotate();
            let (mut a2, _, mut m2) = grant(state, false, None);
            a2.refresh_grant = r2.refresh_grant.clone();
            m2.refresh_grant = r2.refresh_grant.clone();
            m2.refresh_parent = Some(r2.token.clone());
            state
                .tokens
                .store
                .store_refreshed_grant(&r1.token, a2.clone(), r2.clone(), m2.clone())
                .map_err(|e| format!("first rotation: {e:?}"))?;
            observe(state, &a1.token, !retain).await?;
            observe(state, &a2.token, true).await?;
            let mut prepared = r2.clone();
            let r3 = prepared.rotate();
            let (mut a3, _, mut m3) = grant(state, false, None);
            a3.refresh_grant = r3.refresh_grant.clone();
            m3.refresh_grant = r3.refresh_grant.clone();
            m3.refresh_parent = Some(r3.token.clone());
            state
                .tokens
                .store
                .store_refreshed_grant(&r2.token, a3.clone(), r3.clone(), m3.clone())
                .map_err(|e| format!("second rotation: {e:?}"))?;
            observe(state, &a1.token, !retain).await?;
            observe(state, &a2.token, !retain).await?;
            observe(state, &a3.token, true).await?;
            let m1 = state
                .tokens
                .store
                .try_get_bearer_meta(&a1.token)?
                .ok_or("metadata missing")?;
            assert_eq!(
                state
                    .tokens
                    .store
                    .try_revoke_token_for_client(&r3.token, Some(OWNER))?,
                ClientBoundRevocationOutcome::Revoked
            );
            for access in [&a1, &a2, &a3] {
                observe(state, &access.token, false).await?;
            }
            for meta in [&m1, &m2, &m3] {
                let sync = state.tokens.validator.validate_refresh_parent(meta);
                let asynchronous = state
                    .tokens
                    .validator
                    .validate_refresh_parent_async(meta)
                    .await;
                assert_eq!(sync, asynchronous);
                assert!(sync.is_err(), "grant denial always applies");
            }
            Ok(())
        }
        .await;
        fixture.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn shared_redis_refresh_parent_introspection_preserves_no_parent_and_sender_disclosure(
) -> TestResult {
    let fixture = Fixture::new(true).await?;
    let state = &fixture.state;
    let result = async {
        let (access, refresh, meta) = grant(state, false, None);
        assert!(refresh.is_none());
        state
            .tokens
            .store
            .store_issued_grant(access.clone(), refresh, meta)?;
        observe(state, &access.token, true).await?;
        for binding in [
            SenderBinding::DPoP {
                jkt: "public-fixture-jkt".into(),
            },
            SenderBinding::Mtls {
                fingerprint: "ab".repeat(32),
            },
        ] {
            let (access, refresh, meta) = grant(state, true, Some(binding));
            state
                .tokens
                .store
                .store_issued_grant(access.clone(), refresh, meta)?;
            for jwt in [false, true] {
                // Authentication belongs to the introspector. No original-client proof is sent.
                let (status, body) = introspection(state, &access.token, OWNER, jwt).await?;
                assert_eq!(status, StatusCode::OK, "{body}");
                assert_eq!(body["active"], true);
                assert!(body.get("cnf").is_some());
                let (status, body) = introspection(state, &access.token, OTHER, jwt).await?;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body, json!({"active":false}));
            }
        }
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn shared_redis_refresh_parent_introspection_rejects_missing_and_tombstoned_parent(
) -> TestResult {
    let fixture = Fixture::new(true).await?;
    let state = &fixture.state;
    let result = async {
        for missing in [true, false] {
            let (access, refresh, meta) = grant(state, true, None);
            let refresh = refresh.ok_or("refresh missing")?;
            state.tokens.store.store_issued_grant(
                access.clone(),
                Some(refresh.clone()),
                meta.clone(),
            )?;
            let meta = state
                .tokens
                .store
                .try_get_bearer_meta(&access.token)?
                .ok_or("metadata missing")?;
            observe(state, &access.token, true).await?;
            let mut conn = fixture.connection()?;
            if missing {
                let _: usize = conn.del(fixture.key("refresh", &refresh.token))?;
            } else {
                let value = serde_json::to_string(&json!({
                    "token": refresh.token,
                    "expires_at": SystemTime::now() + Duration::from_secs(300)
                }))?;
                let _: () = conn.set_ex(fixture.key("revoked", &refresh.token), value, 300)?;
            }
            assert!(
                state
                    .tokens
                    .store
                    .try_verify_access_token(&access.token)?
                    .is_some(),
                "access lookup remains valid; parent check must reject"
            );
            observe(state, &access.token, false).await?;
            assert_eq!(
                state.tokens.validator.validate_refresh_parent(&meta),
                Err(TokenPolicyError::RefreshParentRevoked)
            );
            assert_eq!(
                state
                    .tokens
                    .validator
                    .validate_refresh_parent_async(&meta)
                    .await,
                Err(TokenPolicyError::RefreshParentRevoked)
            );
        }
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
