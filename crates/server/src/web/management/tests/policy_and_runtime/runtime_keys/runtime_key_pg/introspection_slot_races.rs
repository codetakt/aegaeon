#[tokio::test(flavor = "current_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_introspection_slots_cross_algorithm_races_serialize_last_capacity() -> TestResult {
    let pool = capacity_pg_pool().await?;
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ASYNC_ENV_GUARD.lock().await;
    let _kek = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, URL_SAFE_NO_PAD.encode([0x61; 32]));
    for (first_algorithm, same_algorithm) in [
        ("RS256", false),
        ("EdDSA", false),
        ("RS256", true),
        ("EdDSA", true),
    ] {
        let env = setup_runtime_key_test_environment(&pool).await?;
        let result = slot_race(&pool, &env, first_algorithm, same_algorithm).await;
        let cleanup = cleanup_runtime_key_test_environment(&pool, &env).await;
        finish_runtime_key_pg_test(result, cleanup)?;
    }
    Ok(())
}

fn slot_spawn(
    pool: sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    algorithm: &str,
    create: bool,
) -> Result<
    tokio::task::JoinHandle<
        std::result::Result<crate::management::types::RuntimeKeyMutationResponse, Response>,
    >,
    Box<dyn StdError>,
> {
    let path = runtime_key_test_path(env);
    let session = crate::web::management::state::ManagementSession::human(env.administrator_id, 1);
    let req = slot_create_request(env, algorithm, "race-create", true)?;
    let mut activate = capacity_activate_request(
        env,
        crate::runtime_keys::RuntimeKeyUsage::JwtIntrospectionSigning,
    );
    activate.algorithm = Some(algorithm.into());
    Ok(tokio::spawn(async move {
        if create {
            create_runtime_key_inner(&pool, &path, &req, &session, "slot-race-create").await
        } else {
            activate_next_runtime_key_inner(&pool, &path, &activate, &session, "slot-race-activate")
                .await
        }
    }))
}

async fn slot_race(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    first_algorithm: &str,
    same_algorithm: bool,
) -> TestResult {
    let other = if first_algorithm == "RS256" {
        "EdDSA"
    } else {
        "RS256"
    };
    let path = runtime_key_test_path(env);
    let session = crate::web::management::state::ManagementSession::human(env.administrator_id, 1);
    let second_algorithm = if same_algorithm {
        first_algorithm
    } else {
        other
    };
    for (alg, kid, active) in [
        (first_algorithm, "first-0", true),
        (other, "other-0", true),
        (first_algorithm, "first-1", true),
        (other, "other-1", true),
        (first_algorithm, "first-2", true),
        (second_algorithm, "race-next", false),
    ] {
        create_runtime_key_inner(
            pool,
            &path,
            &slot_create_request(env, alg, kid, active)?,
            &session,
            "slot-race-seed",
        )
        .await
        .map_err(|_| "seed")?;
    }
    let other_before = slot_rows(pool, env, other).await?;
    let audits = runtime_key_audit_payloads(pool, env.environment_id).await?;
    let mut holder = pool.begin().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *holder)
        .await?;
    sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE")
        .bind(env.environment_id)
        .fetch_one(&mut *holder)
        .await?;
    let first = slot_spawn(pool.clone(), env, first_algorithm, true)?;
    let first_pid = match capacity_wait_for_blocker(pool, pid, "FOR UPDATE OF e").await {
        Ok(pid) => pid,
        Err(e) => {
            first.abort();
            holder.rollback().await?;
            return Err(e);
        }
    };
    let second = slot_spawn(pool.clone(), env, second_algorithm, false)?;
    if let Err(e) = capacity_wait_for_blocker(pool, first_pid, "FOR UPDATE OF m, t, a").await {
        first.abort();
        second.abort();
        holder.rollback().await?;
        return Err(e);
    }
    holder.commit().await?;
    let winner = tokio::time::timeout(std::time::Duration::from_secs(15), first)
        .await??
        .map_err(|_| "winner")?;
    let loser = tokio::time::timeout(std::time::Duration::from_secs(15), second).await??;
    assert_eq!(winner.runtime_key.algorithm, first_algorithm);
    capacity_refused(
        loser.err().ok_or("both committed")?,
        crate::runtime_keys::RuntimeKeyUsage::JwtIntrospectionSigning,
    )
    .await?;
    assert!(
        other_before == slot_rows(pool, env, other).await?,
        "other slot changed"
    );
    assert_eq!(
        runtime_key_status(pool, env.environment_id, "race-next").await?,
        "NEXT"
    );
    assert_eq!(
        runtime_key_audit_payloads(pool, env.environment_id)
            .await?
            .len(),
        audits.len() + 1
    );
    Ok(())
}
