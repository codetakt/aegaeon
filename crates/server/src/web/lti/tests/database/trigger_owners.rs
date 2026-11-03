use super::*;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL principals and owned function administration"]
async fn pg_lti_reader_trigger_owner_refuses_drop_and_preserves_intent() -> Result {
    trigger_ownership(false).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL principals and owned function administration"]
async fn pg_lti_writer_trigger_owner_refuses_drop_over_immutable_history() -> Result {
    trigger_ownership(true).await
}

async fn trigger_ownership(management: bool) -> Result {
    let fixture = Fixture::new(false, false).await?;
    let reader = &fixture.state.db_pool;
    let writer = fixture.state.management.database.as_ref().ok_or("writer")?;
    let actor = if management { writer } else { reader };
    let admin = test_support::test_admin_pool(reader).await?;
    let actor_id: String = sqlx::query_scalar("SELECT quote_ident(current_user)")
        .fetch_one(actor)
        .await?;
    let original_owner: String = sqlx::query_scalar("SELECT quote_ident(pg_get_userbyid(proowner)) FROM pg_proc WHERE oid='aegaeon.lti_immutable_record()'::regprocedure")
        .fetch_one(&admin).await?;
    let definition: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('aegaeon.lti_immutable_record()'::regprocedure)",
    )
    .fetch_one(&admin)
    .await?;
    let owner = format!("lti_trigger_owner_{}", Uuid::new_v4().simple());
    let bridge = format!("lti_trigger_bridge_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE ROLE {owner} NOLOGIN; CREATE ROLE {bridge} NOLOGIN; GRANT USAGE ON SCHEMA aegaeon TO {owner}, {bridge}"))
        .execute(&admin).await?;
    let pending = fixture.create().await?;
    let request = fixture.initiate(&pending, false).await?;
    let mut accepted = Vec::new();
    let mut responses = Vec::new();
    for (path, function_owner, membership, removal, effective_role) in [
        ("direct", actor_id.as_str(), String::new(), String::new(), None),
        ("inherit", owner.as_str(), format!("GRANT {owner} TO {actor_id} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"), format!("REVOKE {owner} FROM {actor_id}"), None),
        ("set", owner.as_str(), format!("GRANT {owner} TO {actor_id} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"), format!("REVOKE {owner} FROM {actor_id}"), Some(owner.as_str())),
        ("set-then-inherit", owner.as_str(), format!("GRANT {owner} TO {bridge} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE; GRANT {bridge} TO {actor_id} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"), format!("REVOKE {bridge} FROM {actor_id}; REVOKE {owner} FROM {bridge}"), Some(bridge.as_str())),
    ] {
        if !membership.is_empty() { sqlx::raw_sql(&membership).execute(&admin).await?; }
        sqlx::raw_sql(&format!("ALTER FUNCTION aegaeon.lti_immutable_record() OWNER TO {function_owner}"))
            .execute(&admin).await?;
        let current: String = sqlx::query_scalar("SELECT pg_get_functiondef('aegaeon.lti_immutable_record()'::regprocedure)").fetch_one(&admin).await?;
        assert_eq!(current, definition, "ownership is not in the body fingerprint");
        if database::validate_pools(reader, writer).await.is_ok() { accepted.push(path); }
        if !management {
            responses.push((path, fixture.send("GET", &format!("/lti/authorize?{request}"), true, None, None).await?.status()));
        }
        // Show the real escape without retaining any mutation: the immutable
        // trigger blocks this UPDATE until its owner drops the function CASCADE.
        let statement = "UPDATE aegaeon.lti_identifiers SET context_id='changed-by-trigger-owner' WHERE kind='resource_link'";
        let blocked = sqlx::query(statement).execute(actor).await.expect_err("immutable trigger");
        assert_eq!(blocked.as_database_error().and_then(|e| e.code()).as_deref(), Some("23514"));
        let mut tx = actor.begin().await?;
        if let Some(role) = effective_role {
            sqlx::raw_sql(&format!("SET LOCAL ROLE {role}")).execute(&mut *tx).await?;
        }
        sqlx::raw_sql("DROP FUNCTION aegaeon.lti_immutable_record() CASCADE; RESET ROLE").execute(&mut *tx).await?;
        assert!(sqlx::query(statement).execute(&mut *tx).await?.rows_affected() > 0);
        tx.rollback().await?;
        sqlx::raw_sql(&format!("ALTER FUNCTION aegaeon.lti_immutable_record() OWNER TO {original_owner}"))
            .execute(&admin).await?;
        if !removal.is_empty() { sqlx::raw_sql(&removal).execute(&admin).await?; }
        database::validate_pools(reader, writer).await?;
    }
    // Merely belonging to a function-owning role without ADMIN/SET/INHERIT
    // does not give this login the authority to drop the function.
    sqlx::raw_sql(&format!("ALTER FUNCTION aegaeon.lti_immutable_record() OWNER TO {owner}; GRANT {owner} TO {actor_id} WITH ADMIN FALSE, INHERIT FALSE, SET FALSE"))
        .execute(&admin).await?;
    database::validate_pools(reader, writer).await?;
    sqlx::raw_sql(&format!("ALTER FUNCTION aegaeon.lti_immutable_record() OWNER TO {original_owner}; REVOKE {owner} FROM {actor_id}; DROP OWNED BY {owner}, {bridge}; DROP ROLE {owner}; DROP ROLE {bridge}"))
        .execute(&admin).await?;
    admin.close().await;
    assert!(
        accepted.is_empty(),
        "protected trigger ownership accepted: {accepted:?}"
    );
    for (path, status) in responses {
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{path}: live reader check"
        );
    }
    let response = fixture
        .send(
            "GET",
            &format!("/lti/authorize?{request}"),
            true,
            None,
            None,
        )
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "repair preserves the launch"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL principals and owned role administration"]
async fn pg_lti_serving_principals_reject_host_file_and_program_authority() -> Result {
    let fixture = Fixture::new(false, false).await?;
    let reader = &fixture.state.db_pool;
    let writer = fixture.state.management.database.as_ref().ok_or("writer")?;
    let admin = test_support::test_admin_pool(reader).await?;
    let bridge = format!("lti_host_bridge_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE ROLE {bridge} NOLOGIN"))
        .execute(&admin)
        .await?;
    let mut accepted = Vec::new();
    for (principal, actor) in [("reader", reader), ("writer", writer)] {
        let actor_id: String = sqlx::query_scalar("SELECT quote_ident(current_user)")
            .fetch_one(actor)
            .await?;
        for role in [
            "pg_read_server_files",
            "pg_write_server_files",
            "pg_execute_server_program",
        ] {
            for (path, membership, removal) in [
                ("inherit", format!("GRANT {role} TO {actor_id} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"), format!("REVOKE {role} FROM {actor_id}")),
                ("set", format!("GRANT {role} TO {actor_id} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"), format!("REVOKE {role} FROM {actor_id}")),
                ("set-then-inherit", format!("GRANT {role} TO {bridge} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE; GRANT {bridge} TO {actor_id} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"), format!("REVOKE {bridge} FROM {actor_id}; REVOKE {role} FROM {bridge}")),
            ] {
                sqlx::raw_sql(&membership).execute(&admin).await?;
                if database::validate_pools(reader, writer).await.is_ok() { accepted.push(format!("{principal}/{role}/{path}")); }
                sqlx::raw_sql(&removal).execute(&admin).await?;
                database::validate_pools(reader, writer).await?;
            }
            sqlx::raw_sql(&format!(
                "GRANT {role} TO {actor_id} WITH ADMIN FALSE, INHERIT FALSE, SET FALSE"
            ))
            .execute(&admin)
            .await?;
            database::validate_pools(reader, writer).await?;
            sqlx::raw_sql(&format!("REVOKE {role} FROM {actor_id}"))
                .execute(&admin)
                .await?;
        }
    }
    sqlx::raw_sql(&format!("DROP ROLE {bridge}"))
        .execute(&admin)
        .await?;
    admin.close().await;
    assert!(accepted.is_empty(), "host authority accepted: {accepted:?}");
    Ok(())
}
