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
        Some("application/json;q=broken"),
        Some("application/token-introspection+jwt"),
    ] {
        for id in [None, Some(PUBLIC), Some(OWNER), Some("unknown-client")] {
            for (credentials, attempted) in [
                (vec![], false),
                (
                    vec![
                        ("client_secret", ""),
                        ("client_assertion", ""),
                        ("client_assertion_type", ""),
                    ],
                    false,
                ),
                (vec![("client_secret", " ")], true),
                (vec![("client_assertion", " ")], true),
                (vec![("client_assertion_type", " ")], true),
                (
                    vec![
                        ("client_secret", " "),
                        ("client_assertion", ""),
                        ("client_assertion_type", " "),
                    ],
                    true,
                ),
            ] {
                let mut fields = Vec::new();
                if let Some(id) = id {
                    fields.push(("client_id", id));
                }
                fields.extend(credentials);
                // Empty form values are absent; whitespace is an exact supplied
                // credential and must never become the credentialless category.
                let expected = if attempted {
                    StatusCode::UNAUTHORIZED
                } else {
                    expected
                };
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
async fn shared_redis_introspection_authentication_is_mandatory_across_legacy_flags_and_accept(
) -> TestResult {
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
async fn shared_redis_introspection_signed_builder_rejects_missing_identity_without_negotiation(
) -> TestResult {
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

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn shared_redis_introspection_conflicting_secret_methods_precede_token_access() -> TestResult
{
    for jwt in [false, true] {
        for legacy in [false, true] {
            let fixture = fixture(jwt, legacy).await?;
            let result = async {
                let state = &fixture.state;
                let access = token(state, OWNER)?;
                let broken = token(state, OWNER)?;
                let _: () =
                    fixture
                        .connection()?
                        .set_ex(fixture.key("access", &broken.token), "{", 300)?;
                for accept in [
                    None,
                    Some("application/json"),
                    Some("application/token-introspection+jwt"),
                ] {
                    for basic_secret in [SECRET, "wrong"] {
                        for post_secret in [SECRET, "wrong"] {
                            for value in [&access.token, &broken.token] {
                                let response = request(
                                    state,
                                    value,
                                    &[("client_id", POST), ("client_secret", post_secret)],
                                    Some(&basic(OWNER, basic_secret)),
                                    accept,
                                )
                                .await?;
                                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                                assert_eq!(
                                    response.headers()[header::CONTENT_TYPE],
                                    "application/json"
                                );
                                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                                assert_eq!(response.headers()[header::PRAGMA], "no-cache");
                                assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
                                let body: Value = serde_json::from_slice(
                                    &to_bytes(response.into_body(), 65536).await?,
                                )?;
                                assert_eq!(body["error"], "invalid_request");
                            }
                        }
                    }
                }
                // The malformed token is still observable after valid authentication.
                let response =
                    request(state, &broken.token, &[], Some(&basic(OWNER, SECRET)), None).await?;
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                Ok(())
            }
            .await;
            fixture.finish(result).await?;
        }
    }
    Ok(())
}
