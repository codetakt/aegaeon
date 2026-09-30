use super::*;

async fn resource_request(
    state: &AppState,
    path: &str,
    token: &str,
) -> TestResult<axum::response::Response> {
    let app = Router::new()
        .route(
            "/resource",
            axum::routing::get(crate::web::resource_endpoint::resource),
        )
        .route(
            "/oauth/upstream/refresh",
            post(crate::web::upstream_refresh::upstream_refresh),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::web::runtime_authority_guard::runtime_authority_guard_middleware,
        ))
        .layer(Extension(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            12455,
        )))))
        .with_state(state.clone());
    let builder = if path == "/resource" {
        Request::get(path)
    } else {
        Request::post(path)
    };
    Ok(app
        .oneshot(
            builder
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?)
}

#[tokio::test]
#[ignore = "requires private PostgreSQL"]
async fn client_credentials_online_resource_revocation_and_error_headers() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env, false, false).await?;
        let mut document = policy(false)?;
        let scopes: Vec<String>= crate::web::RESOURCE_SCOPES
            .iter()
            .map(ToString::to_string)
            .collect();
        sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=allowed_scopes || $1 WHERE environment_id=$2 AND client_identifier=$3")
            .bind(&scopes)
            .bind(env.environment_id)
            .bind(CALLER)
            .execute(&pool)
            .await?;
        for audience in [
            crate::resource_audience::protected_resource(&env.issuer_url),
            crate::resource_audience::upstream_refresh(&env.issuer_url)
        ] {
            document.token_exchange.targets.push(
                crate::policy::token_exchange::ExchangeTarget {
                    audience: audience.clone(),
                    resource_aliases: Vec::new()
                }
            );
            document.client_credentials.resource_servers.push(
                crate::policy::client_credentials::ClientCredentialsResourceServer {
                    target_audience: audience.clone(),
                    introspection_clients: Vec::new()
                }
            );
            document.client_credentials.rules.push(
                crate::policy::client_credentials::ClientCredentialsRule {
                    client_id: CALLER.into(),
                    target_audience: audience,
                    scopes: scopes.clone(),
                    default_scopes: scopes.clone(),
                    default_target: false,
                }
            );
        }
        install_policy(&pool, &env, &document).await?;
        let state = reload(&state, &env).await?;
        let mut tokens = Vec::new();
        for path in ["/resource", "/oauth/upstream/refresh"] {
            let audience = format!("{}{path}", env.issuer_url);
            let (status, body) = request(
                &state,
                "/token",
                CALLER,
                SECRET,
                &[("grant_type", "client_credentials"), ("audience", &audience)]
            )
            .await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            tokens.push((
                path,
                body["access_token"].as_str().ok_or("token missing")?.to_string()
            ));
        }
        assert_eq!(
            resource_request(&state, "/resource", &tokens[0].1).await?.status(),
            StatusCode::OK
        );
        let headers = axum::http::HeaderMap::from_iter([(
            header::AUTHORIZATION,
            format!("Bearer {}", tokens[1].1).parse()?
        )]);
        crate::web::upstream_refresh_links::authenticate_upstream_refresh_caller(
            &state,
            &"/oauth/upstream/refresh".parse()?,
            &headers,
            &env.issuer_url,
        )
        .await
        .map_err(|response| format!("upstream caller authorization returned {}", response.status()))?;
        document.client_credentials.rules.retain(|rule| rule.target_audience == TARGET);
        document.client_credentials.resource_servers.retain(|binding| binding.target_audience == TARGET);
        install_policy(&pool, &env, &document).await?;
        let state = reload(&state, &env).await?;
        for (path, token) in tokens {
            let response = resource_request(&state, path, &token).await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::PRAGMA], "no-cache");
            assert!(response.headers()[header::WWW_AUTHENTICATE].to_str()?.contains("invalid_token"));
            let body: Value = serde_json::from_slice(
                &to_bytes(response.into_body(), 1024 * 1024).await?
            )?;
            assert_eq!(body["error"], "invalid_token");
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
