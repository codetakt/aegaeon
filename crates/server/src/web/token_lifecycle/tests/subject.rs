use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn introspection_preserves_exact_subject_without_inventing_username() -> TestResult {
    let fixture = Fixture::new(true).await?;
    let state = &fixture.state;
    let result = async {
        for subject in [
            "usr:8e354c1d-5094-4ac8-9ad2-993b9013c71b",
            "Alex Reader",
            "利用者/e\u{301}/é/🌊",
        ] {
            let (mut access, refresh, mut meta) = grant(state, false, None);
            access.user_id = subject.into();
            meta.user_id = subject.into();
            state
                .tokens
                .store
                .store_issued_grant(access.clone(), refresh, meta)?;
            for signed in [false, true] {
                let (status, body) =
                    introspection(state, &access.token, &reader(state, signed), signed).await?;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body["active"], true);
                assert_eq!(body["sub"], subject);
                assert!(
                    body.get("username").is_none(),
                    "a subject is not username provenance"
                );
            }
            let (status, denied) = introspection(state, &access.token, OWNER, true).await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(denied, json!({"active":false}));
            state.tokens.store.try_revoke_token(&access.token)?;
            for signed in [false, true] {
                let (status, denied) =
                    introspection(state, &access.token, &reader(state, signed), signed).await?;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(denied, json!({"active":false}));
            }
        }
        for signed in [false, true] {
            let (status, denied) = introspection(
                state,
                "unknown-subject-token",
                &reader(state, signed),
                signed,
            )
            .await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(denied, json!({"active":false}));
        }
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
