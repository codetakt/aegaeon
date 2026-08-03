// ── PgTrustAnchorRepository (integration, requires AEGAEON_DATABASE_URL) ─

/// Helper: connect to a test database. Skips only if `AEGAEON_DATABASE_URL` is not set.
///
/// Returns `Ok(None)` if the env var is missing (caller should return early).
async fn test_pg_pool() -> Result<Option<PgPool>, String> {
    let url = match std::env::var("AEGAEON_DATABASE_URL") {
        Ok(url) => url,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("AEGAEON_DATABASE_URL must be valid Unicode".to_string());
        }
    };
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .map(Some)
        .map_err(|err| format!("failed to connect AEGAEON_DATABASE_URL-backed Postgres: {err}"))
}

/// Helper: create a minimal environment row for FK constraints.
/// Returns the `environment_id`.
async fn setup_test_environment(pool: &PgPool) -> Result<Uuid, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let team_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let env_id = Uuid::new_v4();
    let slug = format!("t{}", &team_id.to_string()[..8]);
    let tslug = format!("n{}", &tenant_id.to_string()[..8]);
    let eslug = format!("e{}", &env_id.to_string()[..8]);
    let host = format!("{eslug}.test.example.com");

    // Team
    sqlx::query(
        "INSERT INTO aegaeon.teams (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(team_id)
    .bind(&slug)
    .bind(&slug)
    .execute(&mut *tx)
    .await?;

    // Tenant
    sqlx::query(
            "INSERT INTO aegaeon.tenants (id, team_id, slug, name, region) VALUES ($1, $2, $3, $4, 'us') ON CONFLICT DO NOTHING",
        )
        .bind(tenant_id)
        .bind(team_id)
        .bind(&tslug)
        .bind(&tslug)
        .execute(&mut *tx)
        .await?;

    // Environment
    sqlx::query(
            "INSERT INTO aegaeon.environments (id, tenant_id, name, slug, issuer_host) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(env_id)
        .bind(tenant_id)
        .bind(&eslug)
        .bind(&eslug)
        .bind(&host)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(env_id)
}

/// Helper: clean up test federation data and the minimal FK parent rows.
async fn cleanup_test_environment(pool: &PgPool, env_id: Uuid) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let tenant_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM aegaeon.environments WHERE id = $1")
            .bind(env_id)
            .fetch_optional(&mut *tx)
            .await?;
    let team_id: Option<Uuid> = match tenant_id {
        Some(tenant_id) => {
            sqlx::query_scalar("SELECT team_id FROM aegaeon.tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?
        }
        None => None,
    };

    sqlx::query("DELETE FROM aegaeon.federation_trust_chains WHERE environment_id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM aegaeon.federation_entity_cache WHERE environment_id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM aegaeon.federation_trust_anchors WHERE environment_id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM aegaeon.environments WHERE id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await?;

    if let Some(tenant_id) = tenant_id {
        sqlx::query("DELETE FROM aegaeon.tenants WHERE id = $1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(team_id) = team_id {
        sqlx::query("DELETE FROM aegaeon.teams WHERE id = $1")
            .bind(team_id)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await
}

async fn count_entity_cache_rows(pool: &PgPool, env_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*)::bigint FROM aegaeon.federation_entity_cache WHERE environment_id = $1",
    )
    .bind(env_id)
    .fetch_one(pool)
    .await
}

async fn count_trust_chain_cache_rows(pool: &PgPool, env_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*)::bigint FROM aegaeon.federation_trust_chains WHERE environment_id = $1",
    )
    .bind(env_id)
    .fetch_one(pool)
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_trust_anchor_crud() {
    let Some(pool) = must_ok(test_pg_pool().await) else {
        return;
    };
    let env_id = must_ok(setup_test_environment(&pool).await);
    let repo = PgTrustAnchorRepository::new(pool.clone());
    let jwks = sample_jwks_value();

    // List — initially empty
    let list = must_ok(repo.list_for_environment(env_id).await);
    assert!(list.is_empty());

    // Upsert (insert)
    let anchor = must_ok(
        repo.upsert(env_id, "https://ta.test.example.com", &jwks, None)
            .await,
    );
    assert_eq!(anchor.entity_id, "https://ta.test.example.com");
    assert_eq!(anchor.environment_id, env_id);

    // Get
    let fetched = must_ok(repo.get(env_id, "https://ta.test.example.com").await);
    assert!(fetched.is_some());
    assert_eq!(must_some(fetched).entity_id, "https://ta.test.example.com");

    // Get non-existent
    assert!(must_ok(repo.get(env_id, "https://no.example.com").await).is_none());

    // List
    assert_eq!(must_ok(repo.list_for_environment(env_id).await).len(), 1);

    // Upsert (update)
    let new_jwks = json!({"keys": []});
    let updated = must_ok(
        repo.upsert(env_id, "https://ta.test.example.com", &new_jwks, None)
            .await,
    );
    assert_eq!(updated.jwks, new_jwks);
    assert_eq!(must_ok(repo.list_for_environment(env_id).await).len(), 1);

    // Delete
    assert!(must_ok(repo.delete(env_id, "https://ta.test.example.com").await));
    assert!(must_ok(repo.list_for_environment(env_id).await).is_empty());

    // Delete non-existent
    assert!(!must_ok(repo.delete(env_id, "https://ta.test.example.com").await));

    must_ok(cleanup_test_environment(&pool, env_id).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_trust_anchor_environment_isolation() {
    let Some(pool) = must_ok(test_pg_pool().await) else {
        return;
    };
    let env1 = must_ok(setup_test_environment(&pool).await);
    let env2 = must_ok(setup_test_environment(&pool).await);
    let repo = PgTrustAnchorRepository::new(pool.clone());
    let jwks = sample_jwks_value();

    must_ok(
        repo.upsert(env1, "https://ta1.test.example.com", &jwks, None)
            .await,
    );
    must_ok(
        repo.upsert(env2, "https://ta2.test.example.com", &jwks, None)
            .await,
    );
    must_ok(
        repo.upsert(env1, "https://ta3.test.example.com", &jwks, None)
            .await,
    );

    assert_eq!(must_ok(repo.list_for_environment(env1).await).len(), 2);
    assert_eq!(must_ok(repo.list_for_environment(env2).await).len(), 1);
    assert!(must_ok(repo.get(env2, "https://ta1.test.example.com").await).is_none());

    must_ok(cleanup_test_environment(&pool, env1).await);
    must_ok(cleanup_test_environment(&pool, env2).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_trust_anchor_metadata_policy() {
    let Some(pool) = must_ok(test_pg_pool().await) else {
        return;
    };
    let env_id = must_ok(setup_test_environment(&pool).await);
    let repo = PgTrustAnchorRepository::new(pool.clone());
    let jwks = sample_jwks_value();
    let policy = json!({
        "openid_relying_party": {
            "grant_types": { "subset_of": ["authorization_code"] }
        }
    });

    let anchor = must_ok(
        repo.upsert(env_id, "https://ta.test.example.com", &jwks, Some(&policy))
            .await,
    );
    assert_eq!(anchor.metadata_policy, Some(policy.clone()));

    let fetched = must_some(must_ok(
        repo.get(env_id, "https://ta.test.example.com").await,
    ));
    assert_eq!(fetched.metadata_policy, Some(policy));

    must_ok(cleanup_test_environment(&pool, env_id).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_entity_cache_crud_and_ttl() {
    let Some(pool) = must_ok(test_pg_pool().await) else {
        return;
    };
    let env_id = must_ok(setup_test_environment(&pool).await);
    let repo = PgEntityCacheRepository::new(pool.clone());
    let now = current_epoch_secs();
    let parsed =
        json!({"iss": "https://rp.test.example.com", "sub": "https://rp.test.example.com"});

    // Miss
    assert!(must_ok(repo.get(env_id, "https://rp.test.example.com", now).await).is_none());

    // Insert
    must_ok(
        repo.upsert(
            env_id,
            "https://rp.test.example.com",
            "eyJ...",
            &parsed,
            now + 1800,
        )
        .await,
    );

    // Hit
    let cached = must_ok(repo.get(env_id, "https://rp.test.example.com", now).await);
    assert!(cached.is_some());
    let entry = must_some(cached);
    assert_eq!(entry.entity_id, "https://rp.test.example.com");
    assert_eq!(entry.parsed_statement, parsed);

    // Expired — use a "now" far in the future
    assert!(
        must_ok(
            repo.get(env_id, "https://rp.test.example.com", now + 1801)
                .await
        )
        .is_none()
    );

    // Upsert (update)
    must_ok(
        repo.upsert(
            env_id,
            "https://rp.test.example.com",
            "eyJ-v2",
            &json!({"v": 2}),
            now + 3600,
        )
        .await,
    );
    let updated = must_some(must_ok(repo.get(
        env_id,
        "https://rp.test.example.com",
        now,
    )
    .await));
    assert_eq!(updated.entity_configuration_jws, "eyJ-v2");

    must_ok(cleanup_test_environment(&pool, env_id).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_entity_cache_environment_isolation() {
    let Some(pool) = must_ok(test_pg_pool().await) else {
        return;
    };
    let env1 = must_ok(setup_test_environment(&pool).await);
    let env2 = must_ok(setup_test_environment(&pool).await);
    let repo = PgEntityCacheRepository::new(pool.clone());
    let now = current_epoch_secs();

    must_ok(
        repo.upsert(
            env1,
            "https://rp.test.example.com",
            "jws1",
            &json!({}),
            now + 1800,
        )
        .await,
    );

    assert!(must_ok(repo.get(env2, "https://rp.test.example.com", now).await).is_none());
    assert!(must_ok(repo.get(env1, "https://rp.test.example.com", now).await).is_some());

    must_ok(cleanup_test_environment(&pool, env1).await);
    must_ok(cleanup_test_environment(&pool, env2).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_entity_cache_enforces_environment_capacity() {
    let Some(pool) = must_ok(test_pg_pool().await) else {
        return;
    };
    let env_id = must_ok(setup_test_environment(&pool).await);
    let repo = PgEntityCacheRepository::with_max_entries(pool.clone(), 2);
    let now = current_epoch_secs();

    for idx in 1..=3 {
        must_ok(
            repo.upsert(
                env_id,
                &format!("https://e{idx}.test.example.com"),
                &format!("j{idx}"),
                &json!({ "idx": idx }),
                now + 1800,
            )
            .await,
        );
    }

    assert!(must_ok(count_entity_cache_rows(&pool, env_id).await) <= 2);

    must_ok(cleanup_test_environment(&pool, env_id).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_entity_cache_cleanup_expired() {
    let Some(pool) = must_ok(test_pg_pool().await) else {
        return;
    };
    let env_id = must_ok(setup_test_environment(&pool).await);
    let repo = PgEntityCacheRepository::new(pool.clone());
    let now = current_epoch_secs();
    let cleanup_at = now + 150;

    must_ok(
        repo.upsert(
            env_id,
            "https://e1.test.example.com",
            "j1",
            &json!({}),
            now + 100,
        )
        .await,
    );
    must_ok(
        repo.upsert(
            env_id,
            "https://e2.test.example.com",
            "j2",
            &json!({}),
            now + 200,
        )
        .await,
    );

    let removed = must_ok(repo.cleanup_expired(cleanup_at).await);
    assert!(removed >= 1);

    // e2 should still be present
    assert!(
        must_ok(
            repo.get(env_id, "https://e2.test.example.com", cleanup_at)
                .await
        )
        .is_some()
    );

    must_ok(cleanup_test_environment(&pool, env_id).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_trust_chain_cache_crud_and_ttl() {
    let Some(pool) = must_ok(test_pg_pool().await) else {
        return;
    };
    let env_id = must_ok(setup_test_environment(&pool).await);
    let repo = PgTrustChainCacheRepository::new(pool.clone());
    let now = current_epoch_secs();
    let chain_jwts = json!(["jwt1", "jwt2", "jwt3"]);

    // Miss
    assert!(must_ok(
        repo.get(
            env_id,
            "https://rp.test.example.com",
            "https://ta.test.example.com",
            now,
        )
        .await
    )
    .is_none());

    // Insert
    must_ok(
        repo.upsert(
            env_id,
            "https://rp.test.example.com",
            "https://ta.test.example.com",
            &chain_jwts,
            now + 3600,
        )
        .await,
    );

    // Hit
    let cached = must_ok(
        repo.get(
            env_id,
            "https://rp.test.example.com",
            "https://ta.test.example.com",
            now,
        )
        .await,
    );
    assert!(cached.is_some());
    assert_eq!(must_some(cached).chain_jwts, chain_jwts);

    // Expired
    assert!(must_ok(
        repo.get(
            env_id,
            "https://rp.test.example.com",
            "https://ta.test.example.com",
            now + 3601,
        )
        .await
    )
    .is_none());

    // Upsert (update)
    let new_chain = json!(["updated"]);
    must_ok(
        repo.upsert(
            env_id,
            "https://rp.test.example.com",
            "https://ta.test.example.com",
            &new_chain,
            now + 7200,
        )
        .await,
    );
    let updated = must_some(must_ok(repo.get(
        env_id,
        "https://rp.test.example.com",
        "https://ta.test.example.com",
        now,
    )
    .await));
    assert_eq!(updated.chain_jwts, new_chain);

    must_ok(cleanup_test_environment(&pool, env_id).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_trust_chain_cache_environment_isolation() {
    let Some(pool) = must_ok(test_pg_pool().await) else {
        return;
    };
    let env1 = must_ok(setup_test_environment(&pool).await);
    let env2 = must_ok(setup_test_environment(&pool).await);
    let repo = PgTrustChainCacheRepository::new(pool.clone());
    let now = current_epoch_secs();

    must_ok(
        repo.upsert(
            env1,
            "https://rp.test.example.com",
            "https://ta.test.example.com",
            &json!(["c1"]),
            now + 3600,
        )
        .await,
    );

    // env2 cannot see env1's chain
    assert!(must_ok(
        repo.get(
            env2,
            "https://rp.test.example.com",
            "https://ta.test.example.com",
            now,
        )
        .await
    )
    .is_none());

    must_ok(cleanup_test_environment(&pool, env1).await);
    must_ok(cleanup_test_environment(&pool, env2).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_trust_chain_cache_enforces_environment_capacity() {
    let Some(pool) = must_ok(test_pg_pool().await) else {
        return;
    };
    let env_id = must_ok(setup_test_environment(&pool).await);
    let repo = PgTrustChainCacheRepository::with_max_entries(pool.clone(), 2);
    let now = current_epoch_secs();

    for idx in 1..=3 {
        must_ok(
            repo.upsert(
                env_id,
                &format!("https://leaf{idx}.test.example.com"),
                &format!("https://ta{idx}.test.example.com"),
                &json!([format!("jwt{idx}")]),
                now + 3600,
            )
            .await,
        );
    }

    assert!(must_ok(count_trust_chain_cache_rows(&pool, env_id).await) <= 2);

    must_ok(cleanup_test_environment(&pool, env_id).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_trust_chain_cache_cleanup_expired() {
    let Some(pool) = must_ok(test_pg_pool().await) else {
        return;
    };
    let env_id = must_ok(setup_test_environment(&pool).await);
    let repo = PgTrustChainCacheRepository::new(pool.clone());
    let now = current_epoch_secs();
    let cleanup_at = now + 150;

    must_ok(
        repo.upsert(env_id, "leaf1", "ta1", &json!(["jwt-a"]), now + 100)
            .await,
    );
    must_ok(
        repo.upsert(env_id, "leaf2", "ta2", &json!(["jwt-b"]), now + 200)
            .await,
    );

    let removed = must_ok(repo.cleanup_expired(cleanup_at).await);
    assert!(removed >= 1);

    assert!(must_ok(repo.get(env_id, "leaf2", "ta2", cleanup_at).await).is_some());

    must_ok(cleanup_test_environment(&pool, env_id).await);
}
