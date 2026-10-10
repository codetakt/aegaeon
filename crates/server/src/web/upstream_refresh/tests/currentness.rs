use super::cases::reject_without_secrets;
use super::*;
use sqlx::Connection;

pub(super) async fn snapshot(f: &Fixture) -> ResultTest<(Vec<u8>, i64, Option<String>)> {
    Ok(sqlx::query_as("SELECT upstream_refresh_token_encrypted, upstream_refresh_token_generation, last_used_at::text FROM aegaeon.account_links WHERE id=$1")
        .bind(f.link_id).fetch_one(&f.pool).await?)
}

pub(super) async fn wait_for_blocker(pool: &PgPool, blocker: i32) -> ResultTest {
    // The fixture pool has two slots, occupied by the competing transactions.
    // Observation needs an independent connection, not a third pool checkout.
    let mut observer = sqlx::PgConnection::connect_with(&pool.connect_options()).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))")
                .bind(blocker).fetch_one(&mut observer).await?;
            if blocked { return Ok::<(), sqlx::Error>(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await??;
    Ok(())
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_rejects_connection_changes_after_load() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let claims = f.claims()?;
            f.store_callback(&f.callback(&claims, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            let link = f.load().await.map_err(error)?;
            for rotation in [None, Some("private-refresh-rejected")] {
                for (change, restore) in [
                    ("client_id='changed-client'", "client_id='client'"),
                    ("status='DISABLED'", "status='ACTIVE'"),
                    (
                        "connection_identifier='changed'",
                        "connection_identifier='refresh-test'",
                    ),
                    (
                        "client_auth_method='client_secret_basic'",
                        "client_auth_method='none'",
                    ),
                ] {
                    sqlx::query(&format!(
                        "UPDATE aegaeon.connections SET {change} WHERE id=$1"
                    ))
                    .bind(link.upstream_connection_id)
                    .execute(&f.pool)
                    .await?;
                    let before = snapshot(f).await?;
                    let response = f
                        .refresh(&link, Some(&claims), rotation)
                        .await
                        .err()
                        .ok_or("stale connection accepted")?;
                    assert_eq!(response.status(), StatusCode::CONFLICT);
                    reject_without_secrets(response).await?;
                    assert_eq!(before, snapshot(f).await?);
                    sqlx::query(&format!(
                        "UPDATE aegaeon.connections SET {restore} WHERE id=$1"
                    ))
                    .bind(link.upstream_connection_id)
                    .execute(&f.pool)
                    .await?;
                }
                // Lifecycle changes invalidate the active-runtime view even if c is unchanged.
                sqlx::query("UPDATE aegaeon.environments SET status='DELETED' WHERE id=$1")
                    .bind(f.env.environment_id)
                    .execute(&f.pool)
                    .await?;
                let before = snapshot(f).await?;
                let response = f
                    .refresh(&link, None, rotation)
                    .await
                    .err()
                    .ok_or("inactive environment accepted")?;
                assert_eq!(response.status(), StatusCode::CONFLICT);
                reject_without_secrets(response).await?;
                assert_eq!(before, snapshot(f).await?);
                sqlx::query("UPDATE aegaeon.environments SET status='ACTIVE' WHERE id=$1")
                    .bind(f.env.environment_id)
                    .execute(&f.pool)
                    .await?;
            }
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_connection_update_wins_pending_refresh() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let claims = f.claims()?;
            f.store_callback(&f.callback(&claims, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            for rotation in [None, Some("private-refresh-rejected")] {
                let link = f.load().await.map_err(error)?;
                let before = snapshot(f).await?;
                let mut management = f.pool.begin().await?;
                let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *management)
                    .await?;
                sqlx::query(
                    "UPDATE aegaeon.connections SET client_id='changed-client' WHERE id=$1",
                )
                .bind(link.upstream_connection_id)
                .execute(&mut *management)
                .await?;
                let pool = f.pool.clone();
                let issuer = f.env.issuer_url.clone();
                let profile = f.profile.clone();
                let pending = tokio::spawn(async move {
                    persist_upstream_refresh_exchange(
                        &pool,
                        &link,
                        &Fixture::response(None, rotation),
                        &profile,
                        &issuer,
                    )
                    .await
                });
                // Observe the actual database lock wait; a scheduler delay is not evidence.
                wait_for_blocker(&f.pool, blocker).await?;
                management.commit().await?;
                let response = pending
                    .await?
                    .err()
                    .ok_or("concurrent connection change accepted")?;
                assert_eq!(response.status(), StatusCode::CONFLICT);
                reject_without_secrets(response).await?;
                assert_eq!(before, snapshot(f).await?);
                sqlx::query("UPDATE aegaeon.connections SET client_id='client' WHERE id=$1")
                    .bind(f.request.context.connection_id)
                    .execute(&f.pool)
                    .await?;
            }
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_holds_currentness_until_commit() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let claims = f.claims()?;
            f.store_callback(&f.callback(&claims, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            for rotation in [None, Some("private-refresh-next")] {
                for environment in [false, true] {
                    let link = f.load().await.map_err(error)?;
                    let mut refresh = f.pool.begin().await?;
                    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                        .fetch_one(&mut *refresh)
                        .await?;
                    super::super::persistence::lock_current_connection(
                        &mut refresh,
                        &link,
                        &f.profile,
                        &f.env.issuer_url,
                    )
                    .await
                    .map_err(error)?;
                    let pool = f.pool.clone();
                    let id = if environment {
                        f.env.environment_id
                    } else {
                        link.upstream_connection_id
                    };
                    let pending = tokio::spawn(async move {
                        let query = if environment {
                            "UPDATE aegaeon.environments SET status='DELETED' WHERE id=$1"
                        } else {
                            "UPDATE aegaeon.connections SET client_id='changed-client' WHERE id=$1"
                        };
                        sqlx::query(query).bind(id).execute(&pool).await
                    });
                    wait_for_blocker(&f.pool, blocker).await?;
                    super::super::persistence::persist_locked_upstream_refresh_exchange(
                        &mut refresh,
                        &link,
                        &Fixture::response(None, rotation),
                        &f.env.issuer_url,
                    )
                    .await
                    .map_err(error)?;
                    refresh.commit().await?;
                    assert_eq!(pending.await??.rows_affected(), 1);
                    assert_eq!(
                        snapshot(f).await?.1,
                        link.upstream_refresh_token_generation + i64::from(rotation.is_some())
                    );
                    let restore = if environment {
                        "UPDATE aegaeon.environments SET status='ACTIVE' WHERE id=$1"
                    } else {
                        "UPDATE aegaeon.connections SET client_id='client' WHERE id=$1"
                    };
                    sqlx::query(restore).bind(id).execute(&f.pool).await?;
                }
            }
            Ok(())
        })
    })
}
