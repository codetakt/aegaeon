async fn membership_test_pool() -> Result<sqlx::PgPool, Box<dyn StdError>> {
    runtime_key_test_pg_pool().await?.ok_or_else(|| {
        io::Error::other("this integration test requires AEGAEON_DATABASE_URL").into()
    })
}

async fn membership_version(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    number: i64,
    status: &str,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO aegaeon.configuration_versions
         (environment_id, version_number, configuration_hash, status,
          configuration_document, created_by_administrator_id)
         SELECT environment_id, $2, $3, $4::aegaeon.configuration_version_status,
                configuration_document, created_by_administrator_id
         FROM aegaeon.configuration_versions WHERE id = $1 RETURNING id",
    )
    .bind(env.configuration_version_id)
    .bind(number)
    .bind(format!("membership-{number}"))
    .bind(status)
    .fetch_one(pool)
    .await
}

async fn seed_configuration_members(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
) -> TestResult {
    let historical = membership_version(pool, env, 2, "ARCHIVED").await?;
    for (name, kind, status, expired, version) in [
        (
            "downstream",
            "DOWNSTREAM",
            "ACTIVE",
            false,
            env.configuration_version_id,
        ),
        (
            "upstream",
            "UPSTREAM",
            "ACTIVE",
            false,
            env.configuration_version_id,
        ),
        (
            "expired",
            "DOWNSTREAM",
            "ACTIVE",
            true,
            env.configuration_version_id,
        ),
        (
            "retired",
            "DOWNSTREAM",
            "RETIRED",
            false,
            env.configuration_version_id,
        ),
        ("historical", "DOWNSTREAM", "ACTIVE", false, historical),
    ] {
        sqlx::query(
            "INSERT INTO aegaeon.oauth_profiles
             (environment_id, configuration_version_id, name, profile_type,
              is_default, allowed_grant_types, token_endpoint_auth_methods_allowed,
              status, expires_at)
             VALUES ($1,$2,$3,$4::aegaeon.oauth_profile_type,$5,
                     ARRAY['authorization_code'],ARRAY['none'],
                     $6::aegaeon.oauth_profile_status,
                     CASE WHEN $7 THEN now() - interval '1 day' ELSE NULL END)",
        )
        .bind(env.environment_id)
        .bind(version)
        .bind(name)
        .bind(kind)
        .bind(name == "downstream" || name == "upstream")
        .bind(status)
        .bind(expired)
        .execute(pool)
        .await?;
    }
    for (name, status, profile, version) in [
        (
            "bound",
            "ACTIVE",
            Some("downstream"),
            env.configuration_version_id,
        ),
        ("default", "ACTIVE", None, env.configuration_version_id),
        (
            "expired",
            "ACTIVE",
            Some("expired"),
            env.configuration_version_id,
        ),
        (
            "retired",
            "ACTIVE",
            Some("retired"),
            env.configuration_version_id,
        ),
        ("deleted", "DELETED", None, env.configuration_version_id),
        ("historical", "ACTIVE", None, historical),
    ] {
        sqlx::query(
            "INSERT INTO aegaeon.clients
             (environment_id, configuration_version_id, client_identifier, name,
              client_type, redirect_uris, allowed_grant_types, allowed_scopes,
              token_endpoint_authentication_method, status, oauth_profile_id)
             VALUES ($1,$2,$3,$3,'PUBLIC',ARRAY['https://client.example/callback'],
                     ARRAY['authorization_code'],ARRAY['openid'],'none',
                     $4::aegaeon.client_status,
                     (SELECT id FROM aegaeon.oauth_profiles WHERE environment_id=$1 AND name=$5))",
        )
        .bind(env.environment_id)
        .bind(version)
        .bind(name)
        .bind(status)
        .bind(profile)
        .execute(pool)
        .await?;
    }
    for (name, status, version) in [
        ("upstream", "ACTIVE", env.configuration_version_id),
        ("bound-upstream", "ACTIVE", env.configuration_version_id),
        ("disabled", "DISABLED", env.configuration_version_id),
        ("deleted", "DELETED", env.configuration_version_id),
        ("historical", "ACTIVE", historical),
    ] {
        sqlx::query(
            "INSERT INTO aegaeon.connections
             (environment_id,configuration_version_id,connection_identifier,name,
              issuer_url,client_id,status,oauth_profile_id)
             VALUES ($1,$2,$3,$3,'https://upstream.example','upstream-client',
                     $4::aegaeon.connection_status,
                     CASE WHEN $3='bound-upstream' THEN (SELECT id FROM aegaeon.oauth_profiles WHERE environment_id=$1 AND name='upstream') ELSE NULL END)",
        ).bind(env.environment_id).bind(version).bind(name).bind(status)
        .execute(pool).await?;
    }
    Ok(())
}

async fn configuration_membership_snapshot(
    pool: &sqlx::PgPool,
    environment: Uuid,
) -> Result<Vec<(String, serde_json::Value)>, sqlx::Error> {
    let mut rows = Vec::new();
    for table in [
        "clients",
        "oauth_profiles",
        "connections",
        "runtime_keys",
        "client_secrets",
    ] {
        let query = format!(
            "SELECT to_jsonb(r) FROM aegaeon.{table} r WHERE environment_id=$1 ORDER BY id"
        );
        let values: Vec<serde_json::Value> = sqlx::query_scalar(&query)
            .bind(environment)
            .fetch_all(pool)
            .await?;
        rows.extend(values.into_iter().map(|row| (table.to_owned(), row)));
    }
    Ok(rows)
}

fn expected_configuration_membership(
    before: &[(String, serde_json::Value)],
    previous: Uuid,
    next: Uuid,
) -> Vec<(String, serde_json::Value)> {
    let mut expected = before.to_vec();
    for (table, row) in &mut expected {
        let live = match table.as_str() {
            "clients" | "oauth_profiles" => row["status"] == "ACTIVE",
            "connections" => row["status"] == "ACTIVE" || row["status"] == "DISABLED",
            _ => false,
        };
        if live && row["configuration_version_id"] == previous.to_string() {
            row["configuration_version_id"] = next.to_string().into();
        }
    }
    expected
}

async fn assert_configuration_runtime_members(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
) -> TestResult {
    let issuer = format!("https://{}", env.issuer_host);
    for client in ["bound", "default"] {
        crate::oauth_profile::resolve_downstream_profile(pool, &issuer, client)
            .await
            .map_err(|err| io::Error::other(format!("profile for {client}: {err:?}")))?;
    }
    for client in ["expired", "retired", "deleted", "historical", "absent"] {
        assert!(
            matches!(
                crate::oauth_profile::resolve_downstream_profile(pool, &issuer, client).await,
                Err(crate::oauth_profile::ProfileError::MissingProfile)
            ),
            "client {client} must not acquire a usable profile"
        );
    }
    crate::oauth_profile::resolve_upstream_profile(pool, &issuer, "upstream")
        .await
        .map_err(|err| io::Error::other(format!("upstream profile: {err:?}")))?;
    crate::oauth_profile::resolve_upstream_profile(pool, &issuer, "bound-upstream")
        .await
        .map_err(|err| io::Error::other(format!("bound upstream profile: {err:?}")))?;
    for connection in ["disabled", "deleted", "historical"] {
        assert!(matches!(
            crate::oauth_profile::resolve_upstream_profile(pool, &issuer, connection).await,
            Err(crate::oauth_profile::ProfileError::MissingProfile)
        ));
    }
    Ok(())
}

async fn cleanup_configuration_members(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
) -> Result<(), sqlx::Error> {
    for table in [
        "dynamic_client_registrations",
        "client_secrets",
        "clients",
        "connections",
        "oauth_profiles",
        "environment_scope_allowlist",
        "environment_key_stores",
    ] {
        sqlx::query(&format!(
            "DELETE FROM aegaeon.{table} WHERE environment_id=$1"
        ))
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    }
    cleanup_runtime_key_test_environment(pool, env).await
}

fn membership_http_request(
    method: Method,
    env: &RuntimeKeyTestEnvironment,
    suffix: &str,
    sid: &str,
    value: serde_json::Value,
) -> Result<Request<Body>, axum::http::Error> {
    Request::builder()
        .method(method)
        .uri(format!(
            "/api/v1/teams/{}/environments/{}/{suffix}",
            env.team_id, env.environment_id
        ))
        .header(header::ORIGIN, "https://admin.example.com")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::COOKIE,
            format!("{MGMT_SESSION_COOKIE_NAME}={sid}; {CSRF_COOKIE_NAME}=membership-csrf"),
        )
        .header("x-csrf-token", "membership-csrf")
        .body(Body::from(value.to_string()))
}

async fn configuration_transition_snapshot(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let mut state = Vec::new();
    for table in [
        "environments",
        "configuration_versions",
        "environment_policies",
        "environment_scope_allowlist",
        "environment_key_stores",
        "clients",
        "oauth_profiles",
        "connections",
        "runtime_keys",
        "client_secrets",
        "audit_events",
    ] {
        let key = if table == "environments" {
            "id"
        } else {
            "environment_id"
        };
        let query = format!(
            "SELECT to_jsonb(r) FROM aegaeon.{table} r WHERE {key}=$1 ORDER BY to_jsonb(r)::text"
        );
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(&query)
            .bind(env.environment_id)
            .fetch_all(pool)
            .await?;
        state.push(serde_json::json!({"table":table,"rows":rows}));
    }
    Ok(state)
}
