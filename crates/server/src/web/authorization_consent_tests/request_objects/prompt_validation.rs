use super::*;

async fn prompt_request(
    state: &AppState,
    sid: &str,
    prompt: &str,
    source: &str,
) -> TestResult<(StatusCode, String)> {
    let plain = authorize_uri(state, Some(prompt))?;
    let jwt = signed_request_with_prompt(state, "prompt-validation", Some(prompt))?;
    let fields: Vec<(String, String)> = if source.contains("jar") {
        vec![("client_id".into(), CLIENT.into()), ("request".into(), jwt)]
    } else {
        serde_urlencoded::from_str(plain.split_once('?').ok_or("query missing")?.1)?
    };
    let uri = if source.starts_with("par") {
        let (status, body) = send(
            state,
            sid,
            "/par",
            Some(
                fields
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect(),
            ),
            None,
        )
        .await?;
        if status != StatusCode::CREATED {
            return Ok((status, body));
        }
        let pushed: Value = serde_json::from_str(&body)?;
        format!(
            "/authorize?{}",
            serde_urlencoded::to_string([
                ("client_id", CLIENT),
                (
                    "request_uri",
                    pushed["request_uri"]
                        .as_str()
                        .ok_or("request_uri missing")?
                ),
            ])?
        )
    } else {
        format!("/authorize?{}", serde_urlencoded::to_string(&fields)?)
    };
    send(state, sid, &uri, None, None).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_prompt_syntax_is_consistent_across_plain_par_and_jar() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required")?;
    for source in ["plain", "par", "jar", "par-jar"] {
        let env = setup_test_environment(&pool).await?;
        let result = async {
            let (state, sid) = fixture(&pool, &env).await?;
            let mut client = state.clients.try_get(CLIENT)?.ok_or("client missing")?;
            client.jwks_pem =
                Some(include_str!("../../../../tests/fixtures/rsa2048-public.pem").into());
            assert!(state.clients.try_update(client)?);
            for prompt in [
                "none consent",
                "login\tconsent",
                "none\nconsent",
                "consent\rlogin",
                "none\u{00a0}consent",
                "consent\0",
                "Consent",
                "select_account",
                "login select_account",
                "select_account consent",
            ] {
                let (status, body) = prompt_request(&state, &sid, prompt, source).await?;
                assert_eq!(
                    status,
                    StatusCode::BAD_REQUEST,
                    "{source} {prompt:?}: {body}"
                );
                assert_eq!(
                    serde_json::from_str::<Value>(&body)?["error"],
                    "invalid_request"
                );
            }
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM aegaeon.authorization_consents WHERE environment_id=$1",
            )
            .bind(env.environment_id)
            .fetch_one(&pool)
            .await?;
            assert_eq!(count, 0, "rejected prompts must not start consent");
            let (status, body) = prompt_request(&state, &sid, "  consent  ", source).await?;
            assert_eq!(status, StatusCode::OK, "{source}: {body}");
            complete_decision(&state, &sid, transaction(&body)?, "approve").await?;
            Ok(())
        }
        .await;
        finish_test(result, cleanup_test_environment(&pool, &env).await)?;
    }
    Ok(())
}

fn invalid_prompt_uri(
    state: &AppState,
    source: &str,
    response_mode: &str,
    redirect_uri: &str,
    prompt: &str,
) -> TestResult<String> {
    const ECHO: &str = "prompt-error-state";
    let fields = if source == "jar" {
        let jwt = signed_request_with_prompt(state, "prompt-validation", Some(prompt))?;
        let payload = jwt.split('.').nth(1).ok_or("request payload missing")?;
        let mut claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
        claims["response_mode"] = json!(response_mode);
        claims["redirect_uri"] = json!(redirect_uri);
        claims["state"] = json!(ECHO);
        let jwt = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_pem(include_bytes!(
                "../../../../tests/fixtures/rsa2048-private.pk8.pem"
            ))?,
        )?;
        vec![
            ("client_id".to_string(), CLIENT.to_string()),
            ("request".into(), jwt),
        ]
    } else {
        let uri = authorize_uri(state, Some(prompt))?;
        let mut fields: Vec<(String, String)> =
            serde_urlencoded::from_str(uri.split_once('?').ok_or("query missing")?.1)?;
        fields.retain(|(name, _)| name != "state" && name != "redirect_uri");
        fields.extend([
            ("state".into(), ECHO.into()),
            ("redirect_uri".into(), redirect_uri.into()),
            ("response_mode".into(), response_mode.into()),
        ]);
        fields
    };
    Ok(format!(
        "/authorize?{}",
        serde_urlencoded::to_string(fields)?
    ))
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_prompt_errors_preserve_response_mode_and_state() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, sid) = fixture(&pool, &env).await?;
        let mut client = state.clients.try_get(CLIENT)?.ok_or("client missing")?;
        client.jwks_pem =
            Some(include_str!("../../../../tests/fixtures/rsa2048-public.pem").into());
        assert!(state.clients.try_update(client)?);
        for strict in [false, true] {
            Arc::make_mut(&mut state.cfg).strict_authorize_redirect = strict;
            for source in ["plain", "jar"] {
                for mode in ["query", "form_post"] {
                    for registered in [true, false] {
                        let redirect_uri = if registered {
                            "https://client.example.com/callback"
                        } else {
                            "https://unregistered.invalid/callback"
                        };
                        for prompt in ["none consent", "login\tconsent", "select_account"] {
                            let uri =
                                invalid_prompt_uri(&state, source, mode, redirect_uri, prompt)?;
                            let app = crate::web::router::build_router(state.clone()).layer(
                                Extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345)))),
                            );
                            let response = app
                                .oneshot(
                                    Request::get(&uri)
                                        .header(
                                            header::COOKIE,
                                            format!("aegaeon_auth_session={sid}"),
                                        )
                                        .body(Body::empty())?,
                                )
                                .await?;
                            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                            let status = response.status();
                            let location = response
                                .headers()
                                .get(header::LOCATION)
                                .map(|value| value.to_str().map(str::to_string))
                                .transpose()?;
                            let body = String::from_utf8(
                                to_bytes(response.into_body(), 1024 * 1024).await?.to_vec(),
                            )?;
                            if registered && mode == "form_post" {
                                assert_eq!(status, StatusCode::OK, "{source}: {body}");
                                assert!(body.contains(&format!("action=\"{redirect_uri}\"")));
                                assert!(body.contains("name=\"error\" value=\"invalid_request\""));
                                assert!(
                                    body.contains("name=\"state\" value=\"prompt-error-state\"")
                                );
                                assert!(!body.contains("name=\"code\""));
                            } else if registered && strict {
                                assert!(status.is_redirection(), "{source}: {body}");
                                let url = url::Url::parse(
                                    location.as_deref().ok_or("redirect missing")?,
                                )?;
                                let mut callback = url.clone();
                                callback.set_query(None);
                                assert_eq!(callback.as_str(), redirect_uri);
                                let params = url
                                    .query_pairs()
                                    .collect::<std::collections::HashMap<_, _>>();
                                assert_eq!(
                                    params.get("error").map(AsRef::as_ref),
                                    Some("invalid_request")
                                );
                                assert_eq!(
                                    params.get("state").map(AsRef::as_ref),
                                    Some("prompt-error-state")
                                );
                                assert!(!params.contains_key("code"));
                            } else {
                                assert_eq!(status, StatusCode::BAD_REQUEST, "{source}: {body}");
                                assert!(location.is_none());
                                let value: Value = serde_json::from_str(&body)?;
                                assert_eq!(value["error"], "invalid_request");
                                assert_eq!(value["state"], "prompt-error-state");
                                assert!(value.get("code").is_none());
                            }
                        }
                    }
                }
            }
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.authorization_consents WHERE environment_id=$1",
        )
        .bind(env.environment_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(count, 0);
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
