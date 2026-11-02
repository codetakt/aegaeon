use super::*;

async fn response(
    state: &AppState,
    sid: &str,
    uri: &str,
) -> TestResult<(StatusCode, Option<String>, String)> {
    let app = crate::web::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    let response = app
        .oneshot(
            Request::get(uri)
                .header(header::COOKIE, format!("aegaeon_auth_session={sid}"))
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().map(str::to_owned))
        .transpose()?;
    let body = String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await?.to_vec())?;
    Ok((status, location, body))
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn oauth_forms_response_modes_are_exact_on_plain_and_signed_authorization() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, sid) = fixture(&pool, &env).await?;
        update_test_policy(&mut state, |p| p.strict_authorize_redirect = true).await?;
        for source in ["plain", "jar"] {
            for mode in [
                "query",
                "form_post",
                "",
                "Query",
                "FORM_POST",
                " query",
                "form_post ",
                " ",
            ] {
                for registered in [true, false] {
                    let redirect = if registered {
                        "https://client.example.com/callback"
                    } else {
                        "https://unregistered.invalid/callback"
                    };
                    let uri = super::prompt_validation::invalid_prompt_uri(
                        &state,
                        source,
                        mode,
                        redirect,
                        &json!("none consent"),
                    )?;
                    let (status, location, body) = response(&state, &sid, &uri).await?;
                    let supported = matches!(mode, "query" | "form_post")
                        || (source == "plain" && mode.is_empty());
                    let expected_error = if supported {
                        "invalid_request"
                    } else {
                        "unsupported_response_mode"
                    };
                    if !registered {
                        assert_eq!(status, StatusCode::BAD_REQUEST, "{source} {mode:?}: {body}");
                        assert!(location.is_none());
                        assert!(!body.contains("name=\"code\""));
                    } else if mode == "form_post" {
                        assert_eq!(status, StatusCode::OK, "{body}");
                        assert!(body.contains("name=\"error\" value=\"invalid_request\""));
                        assert!(body.contains("name=\"state\" value=\"prompt-error-state\""));
                    } else {
                        assert!(status.is_redirection(), "{source} {mode:?}: {body}");
                        let url = url::Url::parse(location.as_deref().ok_or("trusted redirect")?)?;
                        let params = url
                            .query_pairs()
                            .collect::<std::collections::HashMap<_, _>>();
                        assert_eq!(
                            params.get("error").map(AsRef::as_ref),
                            Some(expected_error),
                            "{source} {mode:?}"
                        );
                        assert_eq!(
                            params.get("state").map(AsRef::as_ref),
                            Some("prompt-error-state")
                        );
                        assert!(!params.contains_key("code"));
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
