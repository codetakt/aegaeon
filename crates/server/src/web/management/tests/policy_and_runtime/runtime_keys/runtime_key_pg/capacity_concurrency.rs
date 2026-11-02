#[tokio::test(flavor = "current_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_runtime_key_capacity_concurrent_mixed_paths_serialize_last_slot() -> TestResult {
    let pool = capacity_pg_pool().await?;
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ASYNC_ENV_GUARD.lock().await;
    let _kek = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, URL_SAFE_NO_PAD.encode([0x61u8; 32]));
    for usage in CAPACITY_USAGES {
        for create_first in [true, false] {
            let env = setup_runtime_key_test_environment(&pool).await?;
            let result = capacity_concurrent_scenario(&pool, &env, usage, create_first).await;
            let cleanup = cleanup_runtime_key_test_environment(&pool, &env).await;
            finish_runtime_key_pg_test(result, cleanup)?;
        }
    }
    Ok(())
}

fn capacity_spawn_mutation(
    pool: sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    usage: crate::runtime_keys::RuntimeKeyUsage,
    create: bool,
) -> Result<
    tokio::task::JoinHandle<Result<crate::management::types::RuntimeKeyMutationResponse, Response>>,
    Box<dyn StdError>,
> {
    let path = runtime_key_test_path(env);
    let admin = env.administrator_id;
    let create_req = capacity_create_request(env, usage, "racing-create", true)?;
    let activate_req = capacity_activate_request(env, usage);
    Ok(tokio::spawn(async move {
        let session = crate::web::management::state::ManagementSession::human(admin, 1);
        if create {
            create_runtime_key_inner(&pool, &path, &create_req, &session, "capacity-create-race")
                .await
        } else {
            activate_next_runtime_key_inner(
                &pool,
                &path,
                &activate_req,
                &session,
                "capacity-activate-race",
            )
            .await
        }
    }))
}

async fn capacity_wait_for_blocker(
    pool: &sqlx::PgPool,
    blocker: i32,
    query_fragment: &str,
) -> Result<i32, Box<dyn StdError>> {
    Ok(tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) AND position($2 in query)>0 AND datname=current_database()")
                .bind(blocker).bind(query_fragment).fetch_optional(pool).await?;
            if let Some(pid) = pid { return Ok::<_, sqlx::Error>(pid); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await??)
}

async fn capacity_concurrent_scenario(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    usage: crate::runtime_keys::RuntimeKeyUsage,
    create_first: bool,
) -> TestResult {
    let path = runtime_key_test_path(env);
    let session = crate::web::management::state::ManagementSession::human(env.administrator_id, 1);
    for index in 0..4 {
        let req = capacity_create_request(env, usage, &format!("seed-{index}"), true)?;
        create_runtime_key_inner(pool, &path, &req, &session, "capacity-seed")
            .await
            .map_err(|_| io::Error::other("capacity seed failed"))?;
    }
    let next_req = capacity_create_request(env, usage, "racing-next", false)?;
    create_runtime_key_inner(pool, &path, &next_req, &session, "capacity-next")
        .await
        .map_err(|_| io::Error::other("capacity NEXT seed failed"))?;
    let before = runtime_key_audit_payloads(pool, env.environment_id).await?;
    let mut holder = pool.begin().await?;
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *holder)
        .await?;
    sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE")
        .bind(env.environment_id)
        .fetch_one(&mut *holder)
        .await?;
    let first = capacity_spawn_mutation(pool.clone(), env, usage, create_first)?;
    let first_blocked = capacity_wait_for_blocker(pool, holder_pid, "FOR UPDATE OF e").await;
    let first_pid = match first_blocked {
        Ok(pid) => pid,
        Err(error) => {
            first.abort();
            holder.rollback().await?;
            return Err(error);
        }
    };
    let second = capacity_spawn_mutation(pool.clone(), env, usage, !create_first)?;
    // The first workflow holds membership/team/admin locks while waiting on the
    // environment. Observe the actual second-to-first chain, not a timing guess.
    let second_blocked = capacity_wait_for_blocker(pool, first_pid, "FOR UPDATE OF m, t, a").await;
    if let Err(error) = second_blocked {
        first.abort();
        second.abort();
        holder.rollback().await?;
        return Err(error);
    }
    holder.commit().await?;
    let winner = tokio::time::timeout(std::time::Duration::from_secs(15), first)
        .await??
        .map_err(|_| io::Error::other("first lock owner failed rotation"))?;
    let loser = tokio::time::timeout(std::time::Duration::from_secs(15), second).await??;
    let response = match loser {
        Ok(_) => return Err(io::Error::other("both competing rotations committed").into()),
        Err(response) => response,
    };
    capacity_refused(response, usage).await?;
    let expected = if create_first {
        "racing-create"
    } else {
        "racing-next"
    };
    assert_eq!(winner.runtime_key.kid, expected);
    capacity_loaded(pool, env, usage, expected, 4).await?;
    let after = runtime_key_audit_payloads(pool, env.environment_id).await?;
    assert_eq!(after.len(), before.len() + 1);
    if create_first {
        assert_eq!(
            runtime_key_status(pool, env.environment_id, "racing-next").await?,
            "NEXT"
        );
    } else {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_keys WHERE environment_id=$1 AND kid='racing-create'")
            .bind(env.environment_id).fetch_one(pool).await?;
        assert_eq!(count, 0);
    }
    Ok(())
}
