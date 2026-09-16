fn timestamp_profile_input() -> super::oauth_profiles_support::OAuthProfileInput {
    super::oauth_profiles_support::OAuthProfileInput {
        name: "timestamp-profile".to_string(),
        description: None,
        profile_type: "DOWNSTREAM".to_string(),
        is_default: false,
        require_pkce: true,
        require_state_parameter: true,
        require_iss_parameter: true,
        sender_constrained: "DPOP".to_string(),
        enforce_refresh_sender_binding: true,
        allowed_grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_methods_allowed: vec!["none".to_string()],
        expires_at: Some("2090-01-01T09:00:00.123+09:00".to_string()),
    }
}

fn check_management_timestamp(value: &str) -> TestResult {
    if value.len() != 24 || !value.ends_with('Z') || !super::audit_time::is_valid_iso8601(value) {
        return Err(io::Error::other(format!("not a UTC millisecond timestamp: {value:?}")).into());
    }
    Ok(())
}

fn check_profile_timestamps(
    profile: &crate::management::types::OAuthProfile,
    expect_expiry: bool,
) -> TestResult {
    assert_eq!(profile.expires_at.is_some(), expect_expiry);
    let value = serde_json::to_value(profile)?;
    check_management_timestamp(&profile.created_at)?;
    check_management_timestamp(&profile.updated_at)?;
    if let Some(expiry) = &profile.expires_at {
        check_management_timestamp(expiry)?;
        if expiry != "2090-01-01T00:00:00.123Z" || value["expiresAt"] != *expiry {
            return Err(
                io::Error::other("profile expiry changed its instant or wire value").into(),
            );
        }
    } else if value.get("expiresAt").is_some() {
        return Err(io::Error::other("unbounded expiry should be omitted").into());
    }
    Ok(())
}

async fn seed_timestamp_profile(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    created_at: &str,
) -> Result<Uuid, sqlx::Error> {
    // Fixed row values let read tests fail independently of the insert response.
    sqlx::query_scalar(
        "INSERT INTO aegaeon.oauth_profiles
         (environment_id, configuration_version_id, name, profile_type,
          allowed_grant_types, token_endpoint_auth_methods_allowed, expires_at, created_at)
         VALUES ($1,$2,'timestamp-profile','DOWNSTREAM',ARRAY['authorization_code'],
                 ARRAY['none'],'2090-01-01T09:00:00.123+09:00',$3::timestamptz)
         RETURNING id",
    )
    .bind(env.environment_id)
    .bind(env.configuration_version_id)
    .bind(created_at)
    .fetch_one(pool)
    .await
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_management_timestamps_profile_insert() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        let mut tx = pool.begin().await?;
        for expiry in [timestamp_profile_input().expires_at, None] {
            let input = super::oauth_profiles_support::OAuthProfileInput {
                expires_at: expiry,
                ..timestamp_profile_input()
            };
            let row = super::oauth_profile_store::insert_oauth_profile_row(
                &mut tx,
                env.environment_id,
                env.configuration_version_id,
                &input,
                "timestamp-insert",
            )
            .await
            .map_err(|_| io::Error::other("profile insertion failed"))?;
            let profile =
                super::oauth_profile_store::oauth_profile_from_row_result(&row, "timestamp-insert")
                    .map_err(|_| io::Error::other("profile mapping failed"))?;
            check_profile_timestamps(&profile, input.expires_at.is_some())?;
        }
        tx.rollback().await?;
        Ok(())
    }
    .await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_management_timestamps_profile_update() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        let id = seed_timestamp_profile(&pool, &env, "2026-01-01T09:00:00.123456+09:00").await?;
        let mut tx = pool.begin().await?;
        for expiry in [timestamp_profile_input().expires_at, None] {
            let input = super::oauth_profiles_support::OAuthProfileInput {
                expires_at: expiry,
                ..timestamp_profile_input()
            };
            let row = super::oauth_profile_store::update_oauth_profile_row(
                &mut tx,
                id,
                env.environment_id,
                &input,
                "timestamp-update",
            )
            .await
            .map_err(|_| io::Error::other("profile update failed"))?
            .ok_or_else(|| io::Error::other("updated profile missing"))?;
            let profile =
                super::oauth_profile_store::oauth_profile_from_row_result(&row, "timestamp-update")
                    .map_err(|_| io::Error::other("profile mapping failed"))?;
            check_profile_timestamps(&profile, input.expires_at.is_some())?;
        }
        tx.rollback().await?;
        Ok(())
    }
    .await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_management_timestamps_profile_load() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        let id = seed_timestamp_profile(&pool, &env, "2026-01-01T09:00:00.123456+09:00").await?;
        let profile = super::oauth_profile_store::load_oauth_profile(
            &pool,
            env.team_id,
            env.environment_id,
            id,
            "timestamp-load",
        )
        .await
        .map_err(|_| io::Error::other("profile loading failed"))?
        .ok_or_else(|| io::Error::other("profile missing"))?;
        check_profile_timestamps(&profile, true)?;
        assert_eq!(profile.created_at, "2026-01-01T00:00:00.123Z");
        Ok(())
    }
    .await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_management_timestamps_profile_http_pagination() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult =
        async {
            // Two distinct instants within one millisecond, then an exact timestamp
            // tie: neither truncation nor a missing UUID tie-break may lose a row.
            for created_at in [
                "2026-01-01T00:00:00.123001Z",
                "2026-01-01T00:00:00.123002Z",
                "2026-01-01T00:00:00.123002Z",
            ] {
                seed_timestamp_profile(&pool, &env, created_at).await?;
            }
            let expected: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM aegaeon.oauth_profiles WHERE environment_id=$1 ORDER BY created_at,id",
        ).bind(env.environment_id).fetch_all(&pool).await?;
            let mgmt = test_management_state();
            let sid = mgmt
                .sessions
                .create(env.administrator_id, crate::util::now_unix_epoch_secs()?)
                .ok_or_else(|| io::Error::other("session creation failed"))?;
            let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
            let mut suffix = "oauthProfiles?pageSize=1".to_string();
            let mut seen = Vec::new();
            let mut profiles = Vec::new();
            for page in 0..expected.len() {
                let response = app
                    .clone()
                    .oneshot(membership_http_request(
                        Method::GET,
                        &env,
                        &suffix,
                        &sid,
                        serde_json::Value::Null,
                    )?)
                    .await?;
                let status = response.status();
                let body = response_json(response).await?;
                if status != StatusCode::OK {
                    return Err(
                        io::Error::other(format!("profile page {page}: {status} {body}")).into(),
                    );
                }
                let rows = body["oauthProfiles"]
                    .as_array()
                    .ok_or_else(|| io::Error::other("profiles missing"))?;
                assert_eq!(rows.len(), 1);
                let profile: crate::management::types::OAuthProfile =
                    serde_json::from_value(rows[0].clone())?;
                seen.push(Uuid::parse_str(&profile.id)?);
                profiles.push(profile);
                if page + 1 < expected.len() {
                    let token = body["pageInfo"]["nextPageToken"]
                        .as_str()
                        .ok_or_else(|| io::Error::other("next page token missing"))?;
                    suffix = format!("oauthProfiles?pageSize=1&pageToken={token}");
                } else {
                    assert!(body["pageInfo"]["nextPageToken"].is_null());
                }
            }
            assert_eq!(
                seen, expected,
                "pagination must visit every row exactly once"
            );
            for profile in profiles {
                check_profile_timestamps(&profile, true)?;
            }
            Ok(())
        }
        .await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_management_timestamps_revoked_client_secret() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        let client_id: Uuid = sqlx::query_scalar(
            "INSERT INTO aegaeon.clients
             (environment_id,configuration_version_id,client_identifier,name,client_type,
              redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method)
             VALUES ($1,$2,$3,'timestamp-client','CONFIDENTIAL',ARRAY['https://client.example/callback'],
                     ARRAY['authorization_code'],ARRAY['openid'],'client_secret_basic') RETURNING id",
        ).bind(env.environment_id).bind(env.configuration_version_id)
            .bind(Uuid::new_v4().to_string()).fetch_one(&pool).await?;
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO aegaeon.client_secrets
                 (environment_id,configuration_version_id,client_id,secret_hash,status,created_at,expires_at)
                 VALUES ($1,$2,$3,'test-only-unused-hash','ACTIVE',
                         '2026-01-01T09:00:00.123456+09:00',$4::timestamptz) RETURNING id",
            ).bind(env.environment_id).bind(env.configuration_version_id).bind(client_id)
                .bind("2090-01-01T09:00:00.123+09:00").fetch_one(&pool).await?;
            let row = sqlx::query(REVOKE_CLIENT_SECRET_ROW_SQL)
                .bind(id).bind(client_id).bind(env.environment_id).bind(env.team_id)
                .fetch_one(&pool).await?;
            let secret = super::client_secret_from_row_result(&row, "timestamp-revoke")
                .map_err(|_| io::Error::other("secret response mapping failed"))?;
            let value = serde_json::to_value(secret)?;
            let created = value["createdAt"].as_str().ok_or_else(|| io::Error::other("createdAt missing"))?;
            check_management_timestamp(created)?;
            assert_eq!(created, "2026-01-01T00:00:00.123Z");
            assert_eq!(value["status"], "REVOKED");
            assert_eq!(value["expiresAt"], "2090-01-01T00:00:00.123Z");
        Ok(())
    }.await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}
