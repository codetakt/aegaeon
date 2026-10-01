use super::*;

async fn refused_spellings(state: &AppState) -> TestResult {
    for grant in crate::policy::SUPPORTED_GRANT_TYPES {
        for spelling in [
            grant.to_ascii_uppercase(),
            format!(" {grant}"),
            format!("{grant} "),
        ] {
            let (status, body) = send(
                state,
                "/token",
                &[("grant_type", &spelling)],
                Some(&basic()),
            )
            .await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{spelling}: {body}");
            assert_eq!(body["error"], "unauthorized_client");
            assert!(body.get("access_token").is_none());
        }
    }
    Ok(())
}
async fn code_and_device(state: &AppState) -> TestResult {
    const RESOURCE: &str = "HTTPS://resource.example:443/a%20b/%2f";
    let req = serde_json::from_value(
        json!({"response_type":"code","client_id":BASIC,"redirect_uri":REDIRECT,"scope":"api.read","resource":RESOURCE,"code_challenge":CHALLENGE,"code_challenge_method":"S256"}),
    )?;
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code(req, "form-user".into())?;
    let f = [
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("code", ""),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", ""),
        ("resource", RESOURCE),
    ];
    for padded in [format!(" {RESOURCE}"), format!("{RESOURCE} ")] {
        let mut invalid = f.to_vec();
        invalid
            .iter_mut()
            .filter(|(k, _)| *k == "resource")
            .for_each(|(_, v)| *v = &padded);
        let (status, body) = send(state, "/token", &invalid, Some(&basic())).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_target");
    }
    let mut missing = f.to_vec();
    missing.retain(|(k, v)| *k != "code" || v.is_empty());
    let (status, body) = send(state, "/token", &missing, Some(&basic())).await?;
    assert!(status.is_client_error(), "{body}");
    let (status, body) = send(state, "/token", &f, Some(&basic())).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string());
    let (status, device) = send(
        state,
        "/device_authorization",
        &[("scope", "api.read")],
        Some(&basic()),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{device}");
    assert!(state.device.code_store.try_approve(
        device["user_code"].as_str().ok_or("user code")?,
        "form-user"
    )?);
    let grant = crate::policy::DEVICE_CODE_GRANT_TYPE;
    let f = [("grant_type", grant), ("device_code", "")];
    let (status, body) = send(state, "/token", &f, Some(&basic())).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
    for padded in [
        format!(" {}", device["device_code"].as_str().ok_or("device code")?),
        format!("{} ", device["device_code"].as_str().ok_or("device code")?),
    ] {
        let (status, body) = send(
            state,
            "/token",
            &[("grant_type", grant), ("device_code", &padded)],
            Some(&basic()),
        )
        .await?;
        assert!(status.is_client_error(), "{body}");
        assert!(body.get("access_token").is_none());
    }
    let mut f = f.to_vec();
    f.push((
        "device_code",
        device["device_code"].as_str().ok_or("device code")?,
    ));
    let (status, body) = send(state, "/token", &f, Some(&basic())).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string());
    Ok(())
}
async fn jwt_grant(state: &AppState) -> TestResult {
    let mut c = claims(state, "/token")?;
    c["iss"] = json!(BASIC);
    c["sub"] = json!("form-user");
    let jwt = sign(&c)?;
    for padded in [format!(" {jwt}"), format!("{jwt} ")] {
        let (status, body) = send(
            state,
            "/token",
            &[
                ("grant_type", crate::policy::JWT_BEARER_GRANT_TYPE),
                ("assertion", &padded),
            ],
            Some(&basic()),
        )
        .await?;
        assert!(status.is_client_error(), "{body}");
        assert!(body.get("access_token").is_none());
    }
    let f = [
        ("grant_type", crate::policy::JWT_BEARER_GRANT_TYPE),
        ("assertion", jwt.as_str()),
        ("assertion", ""),
        ("scope", "api.read"),
    ];
    let (status, body) = send(state, "/token", &f, Some(&basic())).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string());
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn oauth_forms_exact_grants_code_device_jwt_and_case_refusals() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        refused_spellings(&state).await?;
        code_and_device(&state).await?;
        jwt_grant(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
