use super::*;

async fn effective_exchange(state: &AppState, token: &str) -> TestResult {
    let f = [
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("subject_token", token),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("audience", "internal-api"),
    ];
    for padded in [
        format!(" {token}"),
        format!("{token} "),
        format!("\t{token}"),
        format!("{token}\u{00a0}"),
    ] {
        let mut params = f.to_vec();
        params
            .iter_mut()
            .filter(|(k, _)| *k == "subject_token")
            .for_each(|(_, v)| *v = &padded);
        let (status, body) = request(state, &params, true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.get("access_token").is_none());
    }
    for extras in [
        vec![],
        vec![
            ("subject_token", ""),
            ("subject_token_type", ""),
            ("requested_token_type", ""),
            ("actor_token", ""),
            ("actor_token_type", ""),
            ("resource", ""),
            ("audience", ""),
        ],
        vec![
            ("resource", "https://api.example/resource"),
            ("resource", "https://api.example/resource"),
            ("audience", "internal-api"),
        ],
    ] {
        let mut params = f.to_vec();
        params.extend(extras);
        let (status, body) = request(state, &params, true).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["access_token"].is_string());
    }
    for extras in [
        vec![("actor_token", "actor"), ("actor_token_type", "")],
        vec![
            ("actor_token", ""),
            (
                "actor_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
        ],
        vec![("requested_token_type", " ")],
        vec![(
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        )],
        vec![("resource", "https://unknown.example/resource")],
        vec![("audience", "closed-api")],
    ] {
        let mut params = f.to_vec();
        params.extend(extras);
        let (status, body) = request(state, &params, true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.get("access_token").is_none());
    }
    Ok(())
}
async fn effective_refresh(state: &AppState) -> TestResult {
    for scope in [None, Some(""), Some("read")] {
        let initial = grant(state).await?;
        let refresh = initial["refresh_token"].as_str().ok_or("refresh")?;
        for padded in [format!(" {refresh}"), format!("{refresh} ")] {
            let (status, body) = request(
                state,
                &[("grant_type", "refresh_token"), ("refresh_token", &padded)],
                true,
            )
            .await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(body.get("access_token").is_none());
            assert!(
                !state
                    .tokens
                    .store
                    .try_get_refresh_token(refresh)?
                    .ok_or("retained refresh")?
                    .rotated
            );
        }
        let mut f = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("refresh_token", ""),
            ("client_id", ""),
        ];
        if let Some(scope) = scope {
            f.push(("scope", scope));
        }
        let mut invalid = f.clone();
        invalid.push(("scope", "unknown"));
        let (status, body) = request(state, &invalid, true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            !state
                .tokens
                .store
                .try_get_refresh_token(refresh)?
                .ok_or("retained refresh")?
                .rotated
        );
        let (status, body) = request(state, &f, true).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["access_token"].is_string());
        let scopes = body["scope"]
            .as_str()
            .ok_or("scope")?
            .split(' ')
            .collect::<std::collections::BTreeSet<_>>();
        let expected = if scope == Some("read") {
            "read"
        } else {
            SOURCE_SCOPE
        };
        assert_eq!(scopes, expected.split(' ').collect());
    }
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn oauth_forms_exchange_extensions_and_refresh_narrowing() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        let initial = grant(&state).await?;
        effective_exchange(&state, initial["access_token"].as_str().ok_or("source")?).await?;
        effective_refresh(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
