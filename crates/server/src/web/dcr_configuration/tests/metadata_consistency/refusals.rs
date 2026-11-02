use super::*;

async fn scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let app = router(pool, env).await?;
    let base = json!({"redirect_uris":["https://client.example/callback"],"pkce_required":true});
    for (patch, error) in [
        (json!({"redirect_uris":null}), "invalid_redirect_uri"),
        (json!({"redirect_uris":[]}), "invalid_redirect_uri"),
        (
            json!({"redirect_uris":["https://client.example/callback","https://client.example/callback"]}),
            "invalid_redirect_uri",
        ),
        (
            json!({"redirect_uris":[" https://client.example/callback"]}),
            "invalid_redirect_uri",
        ),
        (
            json!({"redirect_uris":["https://client.example/call\tback"]}),
            "invalid_redirect_uri",
        ),
        (
            json!({"grant_types":["authorization_code","authorization_code"]}),
            "invalid_client_metadata",
        ),
        (
            json!({"grant_types":["client_credentials"],"token_endpoint_auth_method":"none"}),
            "invalid_client_metadata",
        ),
        (
            json!({"grant_types":["client_credentials"],"response_types":["code"]}),
            "invalid_client_metadata",
        ),
        (json!({"response_types":[]}), "invalid_client_metadata"),
        (
            json!({"jwks":{"keys":"bad"},"jwks_uri":"not a URL"}),
            "invalid_client_metadata",
        ),
        (
            json!({"jwks":{"keys":"bad"},"jwks_uri":"https://client.example/keys","token_endpoint_auth_method":"none"}),
            "invalid_client_metadata",
        ),
    ] {
        let mut metadata = base.clone();
        for (name, value) in patch.as_object().ok_or("patch")? {
            metadata[name] = value.clone();
        }
        let before = digest(pool, env).await?;
        let response = app
            .clone()
            .oneshot(request(Method::POST, "/register", None, &metadata)?)
            .await?;
        let status = response.status();
        let value = response_json(response).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
        assert_eq!(value["error"], error);
        assert_eq!(before, digest(pool, env).await?);
    }
    for source in [
        json!({"jwks":{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB"}]}}),
        json!({"jwks_uri":"https://client.example/keys"}),
    ] {
        let mut metadata = base.clone();
        for (name, value) in source.as_object().ok_or("source")? {
            metadata[name] = value.clone();
        }
        let created = post(&app, &metadata).await?;
        let read = read(&app, &created).await?;
        assert_eq!(read["response_types"], json!(["code"]));
        let before = digest(pool, env).await?;
        let update = json!({"client_id":field(&created,"client_id")?, "pkce_required":true,
            "jwks":{"keys":"invalid"}, "jwks_uri":"https://client.example/keys"});
        let response = app
            .clone()
            .oneshot(request(
                Method::PUT,
                &format!("/register/{}", field(&created, "client_id")?),
                Some(field(&created, "registration_access_token")?),
                &update,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await?["error"],
            "invalid_client_metadata"
        );
        assert_eq!(before, digest(pool, env).await?);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB and native DCR parser; actual HTTP refusal snapshots"]
async fn dcr_metadata_router_rejects_inconsistent_metadata_without_writes() -> TestResult {
    let db = Database::create(false).await?;
    let result = async {
        let env = setup_test_dcr_environment(&db.pool).await?;
        scenario(&db.pool, &env).await
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
