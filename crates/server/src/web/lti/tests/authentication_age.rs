use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_retained_authorization_without_age_remains_compatible() -> Result {
    let fixture = Fixture::new(false, false).await?;
    let path = fixture.create().await?;
    let request = fixture.initiate(&path, false).await?;
    let response = fixture
        .send(
            "POST",
            "/lti/authorize",
            false,
            Some("application/x-www-form-urlencoded"),
            Some(request.clone()),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    // Earlier runtimes stored requests without the newly supported field.
    sqlx::query("UPDATE aegaeon.lti_launch_intents SET authorization_request=authorization_request-'max_age' WHERE environment_id=$1")
        .bind(fixture.state.environment_id).execute(&fixture.state.db_pool).await?;
    let response = body(
        fixture
            .send(
                "GET",
                &format!("/lti/authorize?{request}"),
                true,
                None,
                None,
            )
            .await?,
    )
    .await?;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    fixture.verify(&hidden(&response.1, "id_token")?).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_authentication_age_and_acr_preferences_allow_current_launches() -> Result {
    let fixture = Fixture::new(false, false).await?;
    for suffix in [
        "&max_age=120",
        "&acr_values=urn%3Aexample%3Aunsupported",
        "&max_age=120&acr_values=urn%3Aexample%3Aunsupported",
    ] {
        let path = fixture.create().await?;
        let request = fixture.initiate(&path, false).await?;
        let response = body(
            fixture
                .send(
                    "GET",
                    &format!("/lti/authorize?{request}{suffix}"),
                    true,
                    None,
                    None,
                )
                .await?,
        )
        .await?;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        let claims = fixture.verify(&hidden(&response.1, "id_token")?).await?;
        let now = crate::util::now_unix_epoch_secs()?;
        let authenticated = claims["auth_time"].as_u64().ok_or("auth_time")?;
        assert!(authenticated <= now && now - authenticated <= 120);
        assert!(
            claims.get("acr").is_none(),
            "preference is not achieved authentication"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_stale_authentication_age_survives_post_continuation() -> Result {
    for post in [false, true] {
        let mut fixture = Fixture::new(false, false).await?;
        fixture.session = fixture
            .state
            .browser_auth
            .auth_sessions
            .try_create(
                "lti-user",
                crate::web::AuthSessionTimes::local(crate::util::now_unix_epoch_secs()? - 120),
                None,
                None,
                None,
            )?
            .ok_or("old authenticated session")?;
        let path = fixture.create().await?;
        let request = format!("{}&max_age=60", fixture.initiate(&path, false).await?);
        let response = if post {
            let response = fixture
                .send(
                    "POST",
                    "/lti/authorize",
                    false,
                    Some("application/x-www-form-urlencoded"),
                    Some(request.clone()),
                )
                .await?;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let continuation = response.headers()["location"].to_str()?.to_owned();
            fixture.send("GET", &continuation, true, None, None).await?
        } else {
            fixture
                .send(
                    "GET",
                    &format!("/lti/authorize?{request}"),
                    true,
                    None,
                    None,
                )
                .await?
        };
        let response = body(response).await?;
        assert_eq!(hidden(&response.1, "error")?, "login_required");
        assert!(!response.1.contains("name=\"id_token\""));
        let (status, retained): (String, Option<serde_json::Value>) = sqlx::query_as(
            "SELECT status,authorization_request FROM aegaeon.lti_launch_intents WHERE environment_id=$1"
        ).bind(fixture.state.environment_id).fetch_one(&fixture.state.db_pool).await?;
        assert_eq!(status, "initiated");
        if post {
            assert_eq!(retained.ok_or("retained authorization")?["max_age"], "60");
        } else {
            // Refusal does not consume a valid intent; a later valid request can succeed.
            let response = body(
                fixture
                    .send(
                        "GET",
                        &format!(
                            "/lti/authorize?{}",
                            request.replace("max_age=60", "max_age=180")
                        ),
                        true,
                        None,
                        None,
                    )
                    .await?,
            )
            .await?;
            fixture.verify(&hidden(&response.1, "id_token")?).await?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_zero_and_invalid_authentication_age_return_protocol_errors() -> Result {
    let fixture = Fixture::new(false, false).await?;
    for (value, error) in [
        ("0", "login_required"),
        ("-1", "invalid_request"),
        ("1.5", "invalid_request"),
    ] {
        let path = fixture.create().await?;
        let request = fixture.initiate(&path, false).await?;
        let response = body(
            fixture
                .send(
                    "GET",
                    &format!("/lti/authorize?{request}&max_age={value}"),
                    true,
                    None,
                    None,
                )
                .await?,
        )
        .await?;
        assert_eq!(hidden(&response.1, "error")?, error);
        assert!(!response.1.contains("name=\"id_token\""));
    }
    Ok(())
}
