use super::*;

async fn missing_cases(fixture: &Fixture) -> TestResult {
    let state = &fixture.state;
    let access = token(state, PUBLIC)?;
    let broken = token(state, OWNER)?;
    let _: () = fixture
        .connection()?
        .set_ex(fixture.key("access", &broken.token), "{", 300)?;
    let expected = if state.cfg.jwt_runtime().introspection_enabled() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::UNAUTHORIZED
    };
    for accept in [
        None,
        Some("application/json"),
        Some("application/token-introspection+jwt"),
    ] {
        for id in [None, Some(PUBLIC), Some(OWNER), Some("unknown-client")] {
            for blank in [false, true] {
                let mut fields = Vec::new();
                if let Some(id) = id {
                    fields.push(("client_id", id));
                }
                if blank {
                    fields.extend([
                        ("client_secret", " "),
                        ("client_assertion", ""),
                        ("client_assertion_type", " "),
                    ]);
                }
                for value in [&access.token, &broken.token] {
                    error(
                        request(state, value, &fields, None, accept).await?,
                        state,
                        expected,
                    )
                    .await?;
                }
            }
        }
    }
    // Separate direct-library control: local helper errors still yield false-only.
    assert_eq!(
        state.tokens.validator.introspect_token(&broken.token),
        json!({"active":false})
    );
    // The failed Redis observation is reachable after genuine authentication.
    let response = request(state, &broken.token, &[], Some(&basic(OWNER, SECRET)), None).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(body["error"], "temporarily_unavailable");
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn introspection_authentication_is_mandatory_across_legacy_flags_and_accept() -> TestResult {
    for jwt in [false, true] {
        for legacy in [false, true] {
            let fixture = fixture(jwt, legacy).await?;
            let result = missing_cases(&fixture).await;
            fixture.finish(result).await?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn introspection_signed_builder_rejects_missing_identity_without_negotiation() -> TestResult {
    let fixture = fixture(true, false).await?;
    let result = async {
        for caller in [None, Some("")] {
            let response = jwt_introspection::build_jwt_introspection_response(
                &fixture.state,
                &json!({"active":false}),
                caller,
            );
            error(response, &fixture.state, StatusCode::BAD_REQUEST).await?;
        }
        // Form admission retains precedence over the new authentication boundary.
        let response = request(
            &fixture.state,
            "token",
            &[("client_id", PUBLIC), ("client_id", PUBLIC)],
            None,
            None,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "invalid_request");
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
