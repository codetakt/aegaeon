use super::*;

async fn refused(state: &AppState, encoded: &str, auth: Option<&str>) -> TestResult {
    let before = par_count(state)?;
    let (status, body) = send_raw(state, "/par", encoded, auth).await?;
    assert!(status.is_client_error(), "{body}");
    assert!(body.get("request_uri").is_none());
    assert!(
        matches!(
            body["error"].as_str(),
            Some("invalid_request" | "invalid_client")
        ),
        "{body}"
    );
    assert_eq!(par_count(state)?, before);
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn pushed_response_modes_reject_invalid_effective_inputs_before_storage() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        let auth = basic();
        let mut pairs = fields("/par", "");
        pairs.retain(|(key, _)| !key.starts_with("client_assertion"));
        for (key, value) in &mut pairs {
            if *key == "client_id" {
                *value = BASIC;
            }
        }
        pairs.push(("iss", state.issuer.as_str()));
        let encoded = serde_urlencoded::to_string(&pairs)?;
        for extra in [
            "request_uri=urn%3Aexample%3Aold",
            "%72equest_uri=urn%3Aexample%3Aold",
            "request_uri=&request_uri=urn%3Aexample%3Aold",
            "request_uri=one&request_uri=two",
            "response_mode=fragment",
            "response_mode=FORM_POST",
            "response_mode=%20query",
            "response_mode=query%20",
            "response_mode=query&response_mode=form_post",
        ] {
            refused(&state, &format!("{encoded}&{extra}"), Some(&auth)).await?;
        }
        for key in ["response_type", "code_challenge_method"] {
            let without: Vec<_> = pairs.iter().copied().filter(|(k, _)| *k != key).collect();
            let raw = serde_urlencoded::to_string(without)?;
            refused(&state, &raw, Some(&auth)).await?;
            refused(&state, &format!("{raw}&{key}="), Some(&auth)).await?;
        }
        refused(&state, &encoded, None).await?;
        let wrong = encoded.replace(BASIC, CLIENT);
        refused(&state, &wrong, Some(&auth)).await?;
        let malformed = encoded.replace(CHALLENGE, "short");
        refused(&state, &malformed, Some(&auth)).await?;
        for extra in [
            "request_uri=",
            "%72equest_uri=",
            "response_mode=",
            "response_mode=query",
            "response_mode=form_post",
        ] {
            let (status, body) =
                send_raw(&state, "/par", &format!("{encoded}&{extra}"), Some(&auth)).await?;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }
        for mode in ["fragment", "FORM_POST", ""] {
            let request = par::request_object(&state, BASIC)?;
            let payload = request.split('.').nth(1).ok_or("JWT")?;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let mut claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
            claims["response_mode"] = json!(mode);
            let request = sign(&claims)?;
            refused(
                &state,
                &serde_urlencoded::to_string([("request", request.as_str())])?,
                Some(&auth),
            )
            .await?;
        }
        let request = par::request_object(&state, BASIC)?;
        refused(
            &state,
            &serde_urlencoded::to_string([
                ("request", request.as_str()),
                ("response_mode", "form_post"),
            ])?,
            Some(&auth),
        )
        .await?;
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
