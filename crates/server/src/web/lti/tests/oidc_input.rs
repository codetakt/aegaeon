use super::*;
use crate::oidc::{id_token::IdTokenBuilder, required_rs256, IdTokenClaims};

async fn signed_hint(fixture: &Fixture, change: impl FnOnce(&mut IdTokenClaims)) -> Result<String> {
    let mut token = IdTokenBuilder::try_new(
        fixture.state.issuer.to_string(),
        "lti-user".into(),
        "tool".into(),
    )?
    .build();
    change(&mut token.claims);
    let key = &fixture
        .state
        .oidc
        .config
        .as_ref()
        .ok_or("OIDC")?
        .signing_key;
    Ok(required_rs256::sign_required_id_token_async(&token.claims, key).await?)
}

async fn authorize(fixture: &Fixture, request: &str, post: bool) -> Result<(StatusCode, String)> {
    let response = if post {
        let response = fixture
            .send(
                "POST",
                "/lti/authorize",
                false,
                Some("application/x-www-form-urlencoded"),
                Some(request.into()),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()["location"].to_str()?.to_owned();
        fixture.send("GET", &location, true, None, None).await?
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
    body(response).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_oidc_objects_return_errors_only_to_registered_redirects() -> Result {
    let fixture = Fixture::new(false, false).await?;
    let path = fixture.create().await?;
    let request = fixture.initiate(&path, false).await?;
    for (parameter, value, code) in [
        ("request", "synthetic.jwt.object", "request_not_supported"),
        (
            "request_uri",
            "https://unregistered.example/request",
            "request_uri_not_supported",
        ),
        ("registration", "{}", "registration_not_supported"),
    ] {
        let request = format!("{request}&{}", form(&[(parameter, value)]));
        for post in [false, true] {
            let response = if post {
                fixture
                    .send(
                        "POST",
                        "/lti/authorize",
                        true,
                        Some("application/x-www-form-urlencoded"),
                        Some(request.clone()),
                    )
                    .await?
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
            assert_eq!(hidden(&response.1, "error")?, code);
            assert_eq!(hidden(&response.1, "state")?, "opaque-state");
            assert!(!response.1.contains("name=\"id_token\""));
        }
        let wrong = request.replace("tool.example%2Flaunch", "unregistered.example%2Flaunch");
        let response = body(
            fixture
                .send("GET", &format!("/lti/authorize?{wrong}"), true, None, None)
                .await?,
        )
        .await?;
        assert_eq!(response.0, StatusCode::FORBIDDEN);
        assert!(!response.1.contains("<form"));
    }
    let response = authorize(
        &fixture,
        &format!("{request}&claims=%7B%22id_token%22%3A%7B%22email%22%3Anull%7D%7D"),
        false,
    )
    .await?;
    let claims = fixture.verify(&hidden(&response.1, "id_token")?).await?;
    assert!(
        claims.get("email").is_none(),
        "request grants no attribute release"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_signed_id_token_hints_allow_current_sessions_and_post_continuations() -> Result {
    let fixture = Fixture::new(false, false).await?;
    for post in [false, true] {
        for expired in [false, true] {
            let path = fixture.create().await?;
            let request = fixture.initiate(&path, false).await?;
            let hint = signed_hint(&fixture, |claims| {
                if expired {
                    claims.iat -= 3600;
                    claims.exp = claims.iat + 60;
                    claims.nbf = None;
                }
            })
            .await?;
            let request = format!("{request}&{}", form(&[("id_token_hint", &hint)]));
            let response = authorize(&fixture, &request, post).await?;
            assert_eq!(response.0, StatusCode::OK, "{}", response.1);
            let claims = fixture.verify(&hidden(&response.1, "id_token")?).await?;
            assert_eq!(claims["sub"], "lti-user");
            assert_eq!(claims["nonce"], " opaque + nonce ");
            let replay = authorize(&fixture, &request, false).await?;
            assert!(!replay.1.contains("name=\"id_token\""));
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_hints_cannot_authenticate_or_switch_session_owner() -> Result {
    let fixture = Fixture::new(false, false).await?;
    let path = fixture.create().await?;
    let request = fixture.initiate(&path, false).await?;
    for (field, value, expected) in [
        ("sub", "another-user", "login_required"),
        ("iss", "https://other-issuer.example", "invalid_request"),
        ("aud", "other-tool", "invalid_request"),
        ("azp", "other-tool", "invalid_request"),
        ("iat", "future", "invalid_request"),
        ("nbf", "future", "invalid_request"),
        ("events", "logout", "invalid_request"),
    ] {
        let hint = signed_hint(&fixture, |claims| match field {
            "sub" => claims.sub = value.into(),
            "iss" => claims.iss = value.into(),
            "aud" => claims.aud = crate::oidc::Audience::Single(value.into()),
            "azp" => claims.azp = Some(value.into()),
            "iat" => claims.iat += 3600,
            "nbf" => claims.nbf = Some(claims.iat + 3600),
            "events" => {
                claims.additional_claims.insert(
                    "events".into(),
                    serde_json::json!({"http://schemas.openid.net/event/backchannel-logout":{}}),
                );
            }
            _ => unreachable!(),
        })
        .await?;
        let response = authorize(
            &fixture,
            &format!("{request}&{}", form(&[("id_token_hint", &hint)])),
            false,
        )
        .await?;
        assert_eq!(hidden(&response.1, "error")?, expected, "{field}");
        assert!(!response.1.contains("name=\"id_token\""));
    }
    let valid = signed_hint(&fixture, |_| {}).await?;
    let (unsigned, signature) = valid.rsplit_once('.').ok_or("signature")?;
    let tampered = format!(
        "{unsigned}.{}{}",
        if signature.starts_with('A') { 'B' } else { 'A' },
        &signature[1..]
    );
    let response = authorize(
        &fixture,
        &format!("{request}&{}", form(&[("id_token_hint", &tampered)])),
        false,
    )
    .await?;
    assert_eq!(hidden(&response.1, "error")?, "invalid_request");
    let valid_request = format!("{request}&{}", form(&[("id_token_hint", &valid)]));
    let response = body(
        fixture
            .send(
                "GET",
                &format!("/lti/authorize?{valid_request}"),
                false,
                None,
                None,
            )
            .await?,
    )
    .await?;
    assert_eq!(hidden(&response.1, "error")?, "login_required");
    let issued: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='lti.launch.issued.v1'").bind(fixture.state.environment_id).fetch_one(&fixture.state.db_pool).await?;
    assert_eq!(issued, 0);
    let response = authorize(&fixture, &valid_request, false).await?;
    fixture.verify(&hidden(&response.1, "id_token")?).await?;
    Ok(())
}
