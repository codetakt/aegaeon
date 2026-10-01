use super::*;

fn legacy() -> Value {
    let mut value = public_set();
    for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        value["keys"][0][field] = json!("private-sentinel");
    }
    value
}
async fn counts(pool: &PgPool) -> TestResult<(i64, i64, usize)> {
    let rows = sqlx::query(DRY_RUN).fetch_all(pool).await?;
    for row in &rows {
        if row.get::<String, _>("issue") == "private_member" {
            assert!(row.get::<Option<Uuid>, _>("environment_id").is_some());
            assert!(row.get::<Option<Uuid>, _>("client_id").is_some());
            assert_eq!(row.get::<i64, _>("key_index"), 0);
            assert!(["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .contains(&row.get::<String, _>("field").as_str()));
        }
    }
    let summary = rows
        .iter()
        .find(|r| r.get::<String, _>("issue") == "summary")
        .ok_or_else(|| io::Error::other("dry-run summary missing"))?;
    Ok((
        summary.get("private_member_count"),
        summary.get("blocker_count"),
        rows.len(),
    ))
}
async fn apply(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    match sqlx::raw_sql(UPGRADE).execute(&mut *tx).await {
        Ok(_) => tx.commit().await,
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}
fn projection(state: &mut Value) {
    for row in state["registrations"].as_array_mut().unwrap() {
        if let Some(keys) = row["jwks"]["keys"].as_array_mut() {
            for key in keys {
                for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
                    key.as_object_mut().unwrap().remove(field);
                }
            }
        }
    }
}

pub(super) async fn scenario(pool: &PgPool) -> TestResult {
    for migration in PREDECESSOR {
        sqlx::raw_sql(migration).execute(pool).await?;
    }
    let env = setup_test_dcr_environment(pool).await?;
    let inactive = setup_test_dcr_environment(pool).await?;
    for (environment, id, token) in [
        (&env, "owner", "owner-token"),
        (&env, "other", "other-token"),
        (&env, "unchanged", "unchanged-token"),
        (&inactive, "inactive", "inactive-token"),
    ] {
        registration(pool, environment, id, token).await?;
    }
    for (environment, id) in [(&env, "owner"), (&env, "other"), (&inactive, "inactive")] {
        set_jwks(pool, environment, id, &legacy()).await?;
    }
    sqlx::query("UPDATE aegaeon.environments SET active_configuration_version_id=NULL WHERE id=$1")
        .bind(inactive.environment_id)
        .execute(pool)
        .await?;
    assert_eq!(counts(pool).await?, (24, 0, 25));
    // Blockers cause transactional rollback before even valid rows are projected.
    for corrupt in [
        json!(null),
        json!({"keys":null}),
        json!({"keys":[null]}),
        json!([]),
    ] {
        set_jwks(pool, &env, "unchanged", &corrupt).await?;
        let before = stored_state(pool).await?;
        assert_eq!(counts(pool).await?.1, 1);
        assert!(apply(pool).await.is_err());
        assert!(
            stored_state(pool).await? == before,
            "failed upgrade must leave all rows unchanged"
        );
        let absent: bool = sqlx::query_scalar(
            "SELECT to_regprocedure('aegaeon.client_jwks_are_public(jsonb)') IS NULL",
        )
        .fetch_one(pool)
        .await?;
        assert!(absent, "helper creation must roll back too");
    }
    set_jwks(pool, &env, "unchanged", &public_set()).await?;
    router::before_upgrade(pool, &env).await?;
    // Owner repair removed one row's private fields; another active and inactive
    // row remain for migration. Both startup and router loaded them successfully.
    assert_eq!(counts(pool).await?, (16, 0, 17));
    let before_revision =
        crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
            pool,
            &env.issuer_host,
        )
        .await?;
    let mut expected = stored_state(pool).await?;
    projection(&mut expected);
    let mut listener = sqlx::postgres::PgListener::connect_with(pool).await?;
    listener.listen("aegaeon_runtime_authority_changed").await?;
    apply(pool).await?;
    assert!(
        stored_state(pool).await? == expected,
        "migration must preserve order, unrelated JSON, credentials, audit and timestamps"
    );
    assert_eq!(counts(pool).await?, (0, 0, 1));
    let notification =
        tokio::time::timeout(std::time::Duration::from_secs(3), listener.recv()).await??;
    let notice: Value = serde_json::from_str(notification.payload())?;
    assert_eq!(notice["table"], "dynamic_client_registrations");
    assert!(!notification.payload().contains("private-sentinel"));
    let after_revision =
        crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
            pool,
            &env.issuer_host,
        )
        .await?;
    assert!(before_revision.stable_authority_matches(&after_revision));
    assert_ne!(
        before_revision.active_runtime_client_fingerprint(),
        after_revision.active_runtime_client_fingerprint()
    );
    let app = test_router(pool, &env).await?;
    let response = app
        .oneshot(registration_request(
            Method::GET,
            "other",
            Some("other-token"),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()[header::CACHE_CONTROL]
        .to_str()?
        .contains("no-store"));
    let body = response_json(response).await?;
    assert!(body["jwks"] == public_set());
    assert!(!body.to_string().contains("private-sentinel"));
    // Reapplying the exact transformation is a no-op (not replaying Atlas history).
    let update = UPGRADE
        .split("UPDATE aegaeon.dynamic_client_registrations AS registration")
        .nth(1)
        .unwrap()
        .split("ALTER TABLE")
        .next()
        .unwrap();
    let query = format!("UPDATE aegaeon.dynamic_client_registrations AS registration{update}");
    assert_eq!(sqlx::query(&query).execute(pool).await?.rows_affected(), 0);
    assert!(stored_state(pool).await? == expected);
    constraint_controls(pool, &env).await?;
    drop(listener);
    // Desired schema has the same rule, tested separately in this owned DB only.
    sqlx::raw_sql("DROP SCHEMA aegaeon CASCADE")
        .execute(pool)
        .await?;
    sqlx::raw_sql(DESIRED).execute(pool).await?;
    let desired_env = setup_test_dcr_environment(pool).await?;
    registration(pool, &desired_env, "unchanged", "desired-token").await?;
    constraint_controls(pool, &desired_env).await?;
    Ok(())
}

async fn constraint_controls(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let before = stored_state(pool).await?;
    for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let mut bad = public_set();
        bad["keys"][0][field] = Value::Null;
        let err=sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=$1 WHERE environment_id=$2 AND client_identifier='unchanged'").bind(&bad).bind(env.environment_id).execute(pool).await.err().ok_or_else(||io::Error::other("constraint accepted private update"))?;
        assert_eq!(
            err.as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );
        // Delete/reinsert the same row in a rolled-back transaction to exercise INSERT
        // without manufacturing invalid foreign-key or credential fixture fields.
        let mut tx = pool.begin().await?;
        let row:Value=sqlx::query_scalar("DELETE FROM aegaeon.dynamic_client_registrations WHERE environment_id=$1 AND client_identifier='unchanged' RETURNING to_jsonb(dynamic_client_registrations)").bind(env.environment_id).fetch_one(&mut *tx).await?;
        let mut row = row;
        row["jwks"] = bad;
        let err=sqlx::query("INSERT INTO aegaeon.dynamic_client_registrations SELECT * FROM jsonb_populate_record(NULL::aegaeon.dynamic_client_registrations,$1)").bind(row).execute(&mut *tx).await.err().ok_or_else(||io::Error::other("constraint accepted private insert"))?;
        assert_eq!(
            err.as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );
        tx.rollback().await?;
    }
    assert!(stored_state(pool).await? == before);
    for (value, expected) in [
        (Value::Null, false),
        (json!({"keys":[]}), true),
        (json!({"keys":[{}]}), true),
        (json!({"keys":[null]}), false),
        (json!({"keys":[{"kty":"unsupported"}]}), true),
    ] {
        let actual: bool = sqlx::query_scalar("SELECT aegaeon.client_jwks_are_public($1)")
            .bind(value)
            .fetch_one(pool)
            .await?;
        assert_eq!(actual, expected);
    }
    let sql_null: bool = sqlx::query_scalar("SELECT aegaeon.client_jwks_are_public(NULL)")
        .fetch_one(pool)
        .await?;
    assert!(sql_null);
    Ok(())
}
