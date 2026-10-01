//! Isolated PostgreSQL workflow tests: remote acquisition and clock only are injected.
//! These are not router or live-network tests.
use super::*;
use crate::kms::{FederationKeyManager, InMemoryKeyManager};
use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;
const ENTITY: &str = "https://entity.example";

fn signed(key: &InMemoryKeyManager, claims: &Value) -> anyhow::Result<String> {
    let jwk = key
        .federation_public_jwk()
        .ok_or_else(|| anyhow::anyhow!("missing test key"))?;
    let header =
        json!({"alg": key.federation_alg(), "typ": "entity-statement+jwt", "kid": jwk["kid"]});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?)
    );
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign_federation(input.as_bytes())?)
    ))
}
fn claims(key: &InMemoryKeyManager) -> Value {
    json!({"iss": ENTITY, "sub": ENTITY, "iat": NOW - 10, "exp": NOW + 120,
        "jwks": {"keys": [key.federation_public_jwk()]},
        "metadata": {"openid_relying_party": {"client_name": "signed"}}})
}

async fn snapshot(pool: &PgPool, row: Uuid) -> anyhow::Result<(String, i64)> {
    let row: String = sqlx::query_scalar(
        "SELECT to_jsonb(c)::text FROM aegaeon.federation_entity_cache c WHERE id=$1",
    )
    .bind(row)
    .fetch_one(pool)
    .await?;
    let audits = sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events")
        .fetch_one(pool)
        .await?;
    Ok((row, audits))
}

async fn scenario(pool: &PgPool, predecessor: bool) -> anyhow::Result<()> {
    let administrator = Uuid::new_v4();
    let team = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let environment = Uuid::new_v4();
    let row = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.administrators (id,email,password_hash) VALUES ($1,'owner@example.com','fixture')").bind(administrator).execute(pool).await?;
    sqlx::query("INSERT INTO aegaeon.teams (id,name,slug) VALUES ($1,'Fixture','fixture')")
        .bind(team)
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO aegaeon.team_memberships (team_id,administrator_id,role) VALUES ($1,$2,'OWNER')").bind(team).bind(administrator).execute(pool).await?;
    sqlx::query("INSERT INTO aegaeon.tenants (id,team_id,name,slug,region) VALUES ($1,$2,'Fixture','fixture','test')").bind(tenant).bind(team).execute(pool).await?;
    sqlx::query("INSERT INTO aegaeon.environments (id,tenant_id,name,slug,issuer_host) VALUES ($1,$2,'Fixture','fixture','issuer.example')").bind(environment).bind(tenant).execute(pool).await?;
    sqlx::query("INSERT INTO aegaeon.federation_entity_cache (id,environment_id,entity_id,entity_configuration_jws,parsed_statement,fetched_at,expires_at) VALUES ($1,$2,$3,'original','{}',NOW()-INTERVAL '2 hours',NOW()-INTERVAL '1 hour')").bind(row).bind(environment).bind(ENTITY).execute(pool).await?;
    if predecessor {
        upgrade_predecessor(pool, row).await?;
    }
    let contract = table_contract(pool).await?;
    assert!(!contract
        .constraints
        .iter()
        .any(|(name, _)| name == "federation_entity_cache_expires_after_fetch"));
    let params: TeamEnvironmentEntityCachePath = serde_json::from_value(
        json!({"teamId": team.to_string(), "environmentId": environment.to_string(), "entityCacheId": row.to_string()}),
    )?;
    let session = ManagementSession::human(administrator, 0);
    let key = InMemoryKeyManager::new();
    let valid = claims(&key);
    let raw = signed(&key, &valid)?;
    let calls = AtomicUsize::new(0);
    let result = refresh_with(
        pool,
        &params,
        &session,
        Duration::from_secs(3600),
        "valid-refresh",
        |entity| {
            assert_eq!(entity, ENTITY);
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(raw.clone()))
        },
        || Ok(NOW),
    )
    .await
    .map_err(|response| anyhow::anyhow!("valid refresh failed: {:?}", response.status()))?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.entity_id, ENTITY);
    assert_eq!(result.entity_configuration_jws, raw);
    assert_eq!(result.parsed_statement["metadata"], valid["metadata"]);
    let expiration: i64 = sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM expires_at)::bigint FROM aegaeon.federation_entity_cache WHERE id=$1").bind(row).fetch_one(pool).await?;
    assert_eq!(expiration, NOW + 120);
    let audit: Value = sqlx::query_scalar(
        "SELECT data FROM aegaeon.audit_events WHERE request_id='valid-refresh'",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(audit["entityId"], ENTITY);
    assert_eq!(audit["expiresAt"], result.expires_at);
    let before = snapshot(pool, row).await?;
    eprintln!("workflow valid raw, canonical expiry and audit control passed");

    // Each failure traverses production admission and must leave row/audits byte-identical.
    for mode in 0..9 {
        let mut value = valid.clone();
        match mode {
            0 => {
                value["iss"] = json!("https://other.example");
                value["sub"] = value["iss"].clone();
            }
            1 => {
                value["iat"] = json!(NOW - 200);
                value["exp"] = json!(NOW - 61);
            }
            2 => value["iat"] = json!(NOW + 61),
            3 => {
                value
                    .as_object_mut()
                    .ok_or_else(|| anyhow::anyhow!("claims object"))?
                    .remove("iat");
            }
            4 => value["exp"] = value["iat"].clone(),
            7 => {
                value["iat"] = json!(253_402_300_800_i64 - 10);
                value["exp"] = json!(253_402_300_800_i64 + 120);
            }
            _ => {}
        }
        let mut raw = signed(&key, &value)?;
        if mode == 5 {
            let mut parts: Vec<_> = raw.split('.').map(str::to_string).collect();
            let mut signature = URL_SAFE_NO_PAD.decode(&parts[2])?;
            signature[0] ^= 1;
            parts[2] = URL_SAFE_NO_PAD.encode(signature);
            raw = parts.join(".");
        }
        let samples = AtomicUsize::new(0);
        let result = refresh_with(
            pool,
            &params,
            &session,
            Duration::from_secs(3600),
            "rejected-refresh",
            |_| async { Ok(raw) },
            || {
                let call = samples.fetch_add(1, Ordering::SeqCst);
                if mode == 8 {
                    return Err(management_internal_error(
                        "clock-failure",
                        "System clock is outside the supported range",
                    ));
                }
                Ok(if mode == 7 {
                    253_402_300_800
                } else if mode == 6 && call > 0 {
                    NOW + 181
                } else {
                    NOW
                })
            },
        )
        .await;
        let response = result.expect_err("invalid input must reject");
        assert_eq!(
            response.status(),
            if mode >= 7 {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_REQUEST
            },
            "mode {mode}"
        );
        assert_eq!(snapshot(pool, row).await?, before, "mode {mode}");
    }

    eprintln!("workflow invalid raw, time, timestamp range and clock controls passed");

    // Wrong scope is rejected before acquisition, and current roles are checked again after it.
    let other_environment = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.environments (id,tenant_id,name,slug,issuer_host) VALUES ($1,$2,'Other','other','other-issuer.example')").bind(other_environment).bind(tenant).execute(pool).await?;
    let wrong: TeamEnvironmentEntityCachePath = serde_json::from_value(
        json!({"teamId": team.to_string(), "environmentId": other_environment.to_string(), "entityCacheId": row.to_string()}),
    )?;
    let result = refresh_with(
        pool,
        &wrong,
        &session,
        Duration::from_secs(3600),
        "wrong-scope",
        |_| async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(raw.clone())
        },
        || Ok(NOW),
    )
    .await;
    assert_eq!(
        result.expect_err("scope must reject").status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let result = refresh_with(pool, &params, &session, Duration::from_secs(3600), "changed-role", |_| async {
        sqlx::query("UPDATE aegaeon.team_memberships SET role='AUDITOR' WHERE team_id=$1 AND administrator_id=$2").bind(team).bind(administrator).execute(pool).await.map_err(|_| management_internal_error("fixture", "Failed to change fixture role"))?;
        Ok(raw.clone())
    }, || Ok(NOW)).await;
    assert_eq!(
        result.expect_err("role change must reject").status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(snapshot(pool, row).await?, before);
    let result = refresh_with(
        pool,
        &params,
        &session,
        Duration::from_secs(3600),
        "wrong-role",
        |_| async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(raw.clone())
        },
        || Ok(NOW),
    )
    .await;
    assert_eq!(
        result.expect_err("role must reject").status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    sqlx::query(
        "UPDATE aegaeon.team_memberships SET role='OWNER' WHERE team_id=$1 AND administrator_id=$2",
    )
    .bind(team)
    .bind(administrator)
    .execute(pool)
    .await?;

    eprintln!("workflow environment and lifecycle-role controls passed");

    // An audit failure rolls back the preceding update in the same transaction.
    sqlx::query("ALTER TABLE aegaeon.audit_events ADD CONSTRAINT reject_fixture_audit CHECK (request_id <> 'audit-failure')").execute(pool).await?;
    let mut replacement = valid.clone();
    replacement["metadata"]["openid_relying_party"]["client_name"] = json!("replacement");
    let replacement = signed(&key, &replacement)?;
    let result = refresh_with(
        pool,
        &params,
        &session,
        Duration::from_secs(10),
        "audit-failure",
        |_| async { Ok(replacement) },
        || Ok(NOW),
    )
    .await;
    assert_eq!(
        result.expect_err("audit failure must reject").status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(snapshot(pool, row).await?, before);

    eprintln!("workflow audit rollback control passed");

    // Zero TTL and a skew-admitted expired statement never gain a future cache lifetime.
    for (now, ttl, expected) in [(NOW, 0, NOW), (NOW + 121, 3600, NOW + 120)] {
        refresh_with(
            pool,
            &params,
            &session,
            Duration::from_secs(ttl),
            "short-lifetime",
            |_| async { Ok(raw.clone()) },
            || Ok(now),
        )
        .await
        .map_err(|response| {
            anyhow::anyhow!("short lifetime refresh failed: {:?}", response.status())
        })?;
        let expiration: i64 = sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM expires_at)::bigint FROM aegaeon.federation_entity_cache WHERE id=$1").bind(row).fetch_one(pool).await?;
        assert_eq!(expiration, expected);
    }
    // The production-relevant skew case uses observed DB time, not the future fixture clock.
    let db_now: i64 =
        sqlx::query_scalar("SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::bigint")
            .fetch_one(pool)
            .await?;
    let mut expired = valid.clone();
    expired["iat"] = json!(db_now - 100);
    expired["exp"] = json!(db_now - 1);
    let expired_raw = signed(&key, &expired)?;
    let refreshed = refresh_with(
        pool,
        &params,
        &session,
        Duration::from_secs(3600),
        "skew-retention",
        |_| async { Ok(expired_raw) },
        || Ok(db_now),
    )
    .await
    .map_err(|response| anyhow::anyhow!("skew refresh failed: {:?}", response.status()))?;
    let (expiry, elapsed, accurate): (i64, bool, bool) = sqlx::query_as("SELECT EXTRACT(EPOCH FROM expires_at)::bigint, expires_at <= fetched_at, fetched_at >= to_timestamp($2::double precision) AND fetched_at <= clock_timestamp() FROM aegaeon.federation_entity_cache WHERE id=$1").bind(row).bind(db_now).fetch_one(pool).await?;
    assert_eq!(expiry, db_now - 1);
    assert!(elapsed && accurate);
    let audit: Value = sqlx::query_scalar(
        "SELECT data FROM aegaeon.audit_events WHERE request_id='skew-retention'",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(audit["expiresAt"], refreshed.expires_at);
    use crate::federation::{EntityCacheRepository, PgEntityCacheRepository};
    let repository = PgEntityCacheRepository::new(pool.clone());
    assert!(repository.get(environment, ENTITY, expiry).await?.is_none());
    assert!(repository.get(environment, ENTITY, db_now).await?.is_none());
    assert_eq!(repository.cleanup_expired(db_now).await?, 1);
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM aegaeon.federation_entity_cache WHERE id=$1")
            .bind(row)
            .fetch_one(pool)
            .await?;
    assert_eq!(remaining, 0);
    eprintln!("workflow DB-relative skew retention, expired reads and cleanup passed");
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; isolated workflow fixture, no remote transport"]
async fn pg_individual_entity_refresh_admits_raw_before_transactional_update_and_audit(
) -> anyhow::Result<()> {
    let migrated = run_database(true).await?;
    let desired = run_database(false).await?;
    assert_eq!(migrated, desired);
    eprintln!("migrated and desired-schema table contracts match");
    Ok(())
}

async fn run_database(predecessor: bool) -> anyhow::Result<TableContract> {
    let control = PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let name = format!("federation_refresh_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&control)
        .await?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(control.connect_options().as_ref().clone().database(&name))
        .await?;
    eprintln!("owned workflow fixture database: {name}");
    let scenario_pool = pool.clone();
    let result = match tokio::spawn(async move {
        setup_schema(&scenario_pool, predecessor).await?;
        scenario(&scenario_pool, predecessor).await?;
        table_contract(&scenario_pool).await
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(anyhow::anyhow!("workflow fixture task failed: {error}")),
    };
    // Close only owned connections; never force-disconnect other clients or reset shared services.
    let cleanup: anyhow::Result<()> = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                pool.close().await;
                let count: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=$1")
                        .bind(&name)
                        .fetch_one(&control)
                        .await?;
                if pool.size() == 0 && count == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await??;
        sqlx::query(&format!("DROP DATABASE {name}"))
            .execute(&control)
            .await?;
        Ok(())
    }
    .await;
    control.close().await;
    if cleanup.is_ok() {
        eprintln!("removed owned workflow fixture database: {name}");
    }
    match (result, cleanup) {
        (Ok(contract), Ok(())) => Ok(contract),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(anyhow::anyhow!("scenario: {error:#}; cleanup: {cleanup:#}"))
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct TableContract {
    constraints: Vec<(String, String)>,
    columns: Vec<(String, bool)>,
    indexes: Vec<(String, String)>,
}

async fn table_contract(pool: &PgPool) -> anyhow::Result<TableContract> {
    Ok(TableContract {
        constraints: sqlx::query_as("SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='aegaeon.federation_entity_cache'::regclass ORDER BY conname").fetch_all(pool).await?,
        columns: sqlx::query_as("SELECT attname::text, attnotnull FROM pg_attribute WHERE attrelid='aegaeon.federation_entity_cache'::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attname").fetch_all(pool).await?,
        indexes: sqlx::query_as("SELECT indexname::text, indexdef FROM pg_indexes WHERE schemaname='aegaeon' AND tablename='federation_entity_cache' ORDER BY indexname").fetch_all(pool).await?,
    })
}

async fn upgrade_predecessor(pool: &PgPool, row: Uuid) -> anyhow::Result<()> {
    let before = snapshot(pool, row).await?;
    let mut contract = table_contract(pool).await?;
    assert!(contract
        .constraints
        .iter()
        .any(|(name, _)| name == "federation_entity_cache_expires_after_fetch"));
    let failure =
        sqlx::query("UPDATE aegaeon.federation_entity_cache SET expires_at=fetched_at WHERE id=$1")
            .bind(row)
            .execute(pool)
            .await
            .expect_err("predecessor must reject expired-at-acquisition rows");
    assert_eq!(
        failure
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("federation_entity_cache_expires_after_fetch")
    );
    assert_eq!(snapshot(pool, row).await?, before);
    sqlx::raw_sql(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../db/migrations/20261002100000_federation_entity_cache_expiration.sql"
    )))
    .execute(pool)
    .await?;
    assert_eq!(snapshot(pool, row).await?, before);
    contract
        .constraints
        .retain(|(name, _)| name != "federation_entity_cache_expires_after_fetch");
    assert_eq!(table_contract(pool).await?, contract);
    eprintln!("predecessor CHECK rejection and forward migration preservation passed");
    Ok(())
}

async fn setup_schema(pool: &PgPool, predecessor: bool) -> anyhow::Result<()> {
    if predecessor {
        macro_rules! migration {
            ($name:literal) => {
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../db/migrations/",
                    $name
                ))
            };
        }
        for migration in [
            migration!("20260803140000_baseline.sql"),
            migration!("20260909070000_authorization_consents.sql"),
            migration!("20260909090000_authorization_logins.sql"),
            migration!("20260909120000_token_exchange_policy.sql"),
            migration!("20260911090000_application_authorizations.sql"),
            migration!("20260913090000_application_authorization_identities.sql"),
            migration!("20260930090000_client_credentials_policy.sql"),
        ] {
            sqlx::raw_sql(migration).execute(pool).await?;
        }
    } else {
        sqlx::raw_sql(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../db/schema.sql"
        )))
        .execute(pool)
        .await?;
    }
    Ok(())
}
