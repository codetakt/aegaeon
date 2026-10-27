use super::cases::reject_without_secrets;
use super::currentness::{snapshot, wait_for_blocker};
use super::*;

// Reproduce activation's environment-first lock and membership movement with
// unchanged client/profile fields. This exercises SQL interleavings, not the
// management HTTP route or runtime configuration reconstruction.
async fn activate(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, env: Uuid) -> ResultTest<Uuid> {
    let old: Uuid = sqlx::query_scalar(
        "SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1 FOR UPDATE",
    )
    .bind(env)
    .fetch_one(&mut **tx)
    .await?;
    let next: Uuid = sqlx::query_scalar("INSERT INTO aegaeon.configuration_versions(environment_id,version_number,configuration_hash,status,configuration_document) SELECT environment_id,version_number+1,gen_random_uuid()::text,'DRAFT',jsonb_set(configuration_document,'{scopeAllowlist}','[\"openid\",\"profile\"]'::jsonb) FROM aegaeon.configuration_versions WHERE id=$1 RETURNING id")
        .bind(old).fetch_one(&mut **tx).await?;
    for table in ["clients", "oauth_profiles", "connections"] {
        sqlx::query(&format!("UPDATE aegaeon.{table} SET configuration_version_id=$1 WHERE environment_id=$2 AND configuration_version_id=$3"))
            .bind(next).bind(env).bind(old).execute(&mut **tx).await?;
    }
    sqlx::query(
        "UPDATE aegaeon.configuration_versions SET status='ARCHIVED',archived_at=now() WHERE id=$1",
    )
    .bind(old)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE aegaeon.configuration_versions SET status='ACTIVE',activated_at=now() WHERE id=$1",
    )
    .bind(next)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE aegaeon.environments SET active_configuration_version_id=$1 WHERE id=$2")
        .bind(next)
        .bind(env)
        .execute(&mut **tx)
        .await?;
    Ok(next)
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_activation_rejects_loaded_version() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let claims = f.claims()?;
            f.store_callback(&f.callback(&claims, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            for rotation in [None, Some("private-refresh-next")] {
                for concurrent in [false, true] {
                    let link = load_upstream_refresh_link(
                        &f.pool,
                        &fixture_upstream_refresh_caller(f.user.clone(), f.caller.clone()),
                        if concurrent {
                            None
                        } else {
                            Some(&f.request.issuer)
                        },
                        &f.env.issuer_url,
                    )
                    .await
                    .map_err(error)?;
                    let before = snapshot(f).await?;
                    let mut activation = f.pool.begin().await?;
                    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                        .fetch_one(&mut *activation)
                        .await?;
                    let next = activate(&mut activation, f.env.environment_id).await?;
                    assert_ne!(link.configuration_version_id, next);
                    let pool = f.pool.clone();
                    let profile = f.profile.clone();
                    let issuer = f.env.issuer_url.clone();
                    let mut activation = Some(activation);
                    if !concurrent {
                        activation
                            .take()
                            .ok_or("activation transaction")?
                            .commit()
                            .await?;
                    }
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
                    if concurrent {
                        wait_for_blocker(&f.pool, blocker).await?;
                        activation
                            .take()
                            .ok_or("activation transaction")?
                            .commit()
                            .await?;
                    }
                    let rejected = pending
                        .await?
                        .err()
                        .ok_or("configuration activation accepted")?;
                    assert_eq!(rejected.status(), StatusCode::CONFLICT);
                    reject_without_secrets(rejected).await?;
                    assert_eq!(before, snapshot(f).await?);
                    let fresh = f.load().await.map_err(error)?;
                    assert_eq!(fresh.configuration_version_id, next);
                    f.refresh(&fresh, None, rotation).await.map_err(error)?;
                }
            }
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_refresh_serializes_configuration_activation() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let claims = f.claims()?;
            f.store_callback(&f.callback(&claims, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            for rotation in [None, Some("private-refresh-next")] {
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
                let env = f.env.environment_id;
                let pending = tokio::spawn(async move {
                    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
                    let next = activate(&mut tx, env).await.map_err(|e| e.to_string())?;
                    tx.commit().await.map_err(|e| e.to_string())?;
                    Ok::<_, String>(next)
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
                let next = pending.await??;
                assert_eq!(
                    snapshot(f).await?.1,
                    link.upstream_refresh_token_generation + i64::from(rotation.is_some())
                );
                assert_eq!(
                    f.load().await.map_err(error)?.configuration_version_id,
                    next
                );
            }
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_activation_before_load_rejects_stale_runtime() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let claims = f.claims()?;
            f.store_callback(&f.callback(&claims, Some("private-refresh-original"))?)
                .await
                .map_err(error)?;
            let original = f.load().await.map_err(error)?;
            super::super::runtime_version::validate_loaded_runtime_version(
                &f.state,
                &original,
                &f.env.issuer_url,
            )
            .map_err(error)?;
            let mut activation = f.pool.begin().await?;
            let next = activate(&mut activation, f.env.environment_id).await?;
            activation.commit().await?;
            let fresh = f.load().await.map_err(error)?;
            assert_eq!(fresh.configuration_version_id, next);
            let before = snapshot(f).await?;
            let rejected = super::super::runtime_version::validate_loaded_runtime_version(
                &f.state,
                &fresh,
                &f.env.issuer_url,
            )
            .err()
            .ok_or("stale runtime accepted")?;
            assert_eq!(rejected.status(), StatusCode::CONFLICT);
            reject_without_secrets(rejected).await?;
            assert_eq!(before, snapshot(f).await?);
            let loaded = crate::runtime_configuration::load_database_runtime_configuration(
                &f.pool,
                &f.env.issuer_host,
            )
            .await?;
            // run() already holds the key-environment guard; use the actual
            // startup derivation instead of recursively entering the fixture guard.
            let derived = loaded
                .derive_authorization_runtime((*f.state.cfg).clone())
                .await?;
            let mut restarted = f.state.clone();
            restarted.cfg = derived.configuration();
            restarted.oidc.config = derived.oidc();
            restarted.runtime_authority =
                crate::web::RuntimeAuthorityState::from_authorization_runtime(derived);
            super::super::runtime_version::validate_loaded_runtime_version(
                &restarted,
                &fresh,
                &f.env.issuer_url,
            )
            .map_err(error)?;
            Ok(())
        })
    })
}
