use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_own_resource_dpop_presentation_and_current_state() -> TestResult
{
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&f).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (parent, token) = issue(&f, &state, &key, PRIVILEGE).await?;
        let auth = format!("DPoP {token}");
        for (authorization, signed, path, body, expected) in [
            (None, None, PATH.to_string(), "", StatusCode::UNAUTHORIZED),
            (
                Some(auth.clone()),
                None,
                PATH.into(),
                "",
                StatusCode::UNAUTHORIZED,
            ),
            (
                Some(format!("Bearer {token}")),
                Some(proof(&state, &key, &token, "GET", json!({}))?),
                PATH.into(),
                "",
                StatusCode::UNAUTHORIZED,
            ),
            (
                Some(auth.clone()),
                Some(proof(&state, &key, &token, "GET", json!({}))?),
                format!("{PATH}?access_token=forbidden"),
                "",
                StatusCode::BAD_REQUEST,
            ),
            (
                Some(auth.clone()),
                Some(proof(&state, &key, &token, "GET", json!({}))?),
                PATH.into(),
                "credential",
                StatusCode::BAD_REQUEST,
            ),
            (
                Some("DPoP token extra".into()),
                None,
                PATH.into(),
                "",
                StatusCode::BAD_REQUEST,
            ),
        ] {
            assert_eq!(
                get(
                    &state,
                    Method::GET,
                    &path,
                    authorization.as_deref(),
                    signed.as_deref(),
                    body
                )
                .await?
                .0,
                expected
            );
        }
        for changed in [
            json!({"ath":"invalid"}),
            json!({"ath":null}),
            json!({"htm":"POST"}),
            json!({"htu":"https://other.example/organizations/context"}),
            json!({"iat":1}),
        ] {
            let signed = proof(&state, &key, &token, "GET", changed)?;
            assert_eq!(
                get(&state, Method::GET, PATH, Some(&auth), Some(&signed), "")
                    .await?
                    .0,
                StatusCode::UNAUTHORIZED
            );
        }
        let wrong = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let signed = proof(&state, &wrong, &token, "GET", json!({}))?;
        assert_eq!(
            get(&state, Method::GET, PATH, Some(&auth), Some(&signed), "")
                .await?
                .0,
            StatusCode::UNAUTHORIZED
        );
        let signed = proof(&state, &key, &token, "GET", json!({}))?;
        assert_eq!(
            get(&state, Method::GET, PATH, Some(&auth), Some(&signed), "")
                .await?
                .0,
            StatusCode::OK
        );
        assert_eq!(
            get(&state, Method::GET, PATH, Some(&auth), Some(&signed), "")
                .await?
                .0,
            StatusCode::UNAUTHORIZED
        );
        let original = parent["access_token"].as_str().ok_or("original")?;
        let signed = proof(&state, &key, original, "GET", json!({}))?;
        assert_eq!(
            get(
                &state,
                Method::GET,
                PATH,
                Some(&format!("DPoP {original}")),
                Some(&signed),
                ""
            )
            .await?
            .0,
            StatusCode::UNAUTHORIZED
        );
        // Supply a validated disabled configuration; a stale namespace permit
        // would only prove startup mismatch, not the feature-level refusal.
        let mut disabled = state.clone();
        Arc::make_mut(&mut disabled.cfg)
            .authorization_details_types_supported
            .clear();
        disabled.validate_subject_namespace().await?;
        let signed = proof(&state, &key, &token, "GET", json!({}))?;
        assert_eq!(
            get(&disabled, Method::GET, PATH, Some(&auth), Some(&signed), "")
                .await?
                .0,
            StatusCode::UNAUTHORIZED
        );
        crate::organizations::request_work::Admission::drain_for_test().await?;
        let leases = (0..crate::organizations::request_work::MAX_REQUESTS)
            .map(|_| crate::organizations::request_work::Admission::try_acquire())
            .collect::<Result<Vec<_>, _>>()?;
        let signed = proof(&state, &key, &token, "GET", json!({}))?;
        assert_eq!(
            get(&state, Method::GET, PATH, Some(&auth), Some(&signed), "")
                .await?
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(leases);
        let mut tx = f.pool.begin().await?;
        let member =
            crate::organizations::repository::membership(&mut tx, &f.organization, f.users[1])
                .await?
                .ok_or("member")?;
        crate::organizations::repository::update_membership(
            &mut tx,
            f.organization.scope,
            f.organization.id,
            crate::organizations::repository::MembershipUpdate {
                user_id: f.users[1],
                expected_revision: member.revision,
                state: crate::organizations::MembershipState::Suspended,
                roles: member.roles,
            },
            &f.actor,
        )
        .await?;
        tx.commit().await?;
        let signed = proof(&state, &key, &token, "GET", json!({}))?;
        assert_eq!(
            get(&state, Method::GET, PATH, Some(&auth), Some(&signed), "")
                .await?
                .0,
            StatusCode::UNAUTHORIZED
        );
        Ok(())
    }
    .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
