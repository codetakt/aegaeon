use super::*;
use crate::{lti::database, web::test_support};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires restricted reader/writer PostgreSQL and owned role administration"]
async fn pg_lti_attribute_principals_reject_writes_escalation_and_wrong_suppliers() -> Result {
    let fixture = Fixture::new(false, false).await?;
    let reader = &fixture.state.db_pool;
    let writer = fixture.state.management.database.as_ref().ok_or("writer")?;
    database::validate_pools(reader, writer).await?;
    let denied =
        sqlx::query("UPDATE aegaeon.user_attribute_sources SET revision=revision WHERE false")
            .execute(reader)
            .await
            .expect_err("runtime cannot write attributes");
    assert_eq!(
        denied
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("42501")
    );
    sqlx::query("UPDATE aegaeon.user_attribute_sources SET revision=revision WHERE false")
        .execute(writer)
        .await?;
    assert!(database::validate_pools(reader, reader).await.is_err());
    assert!(database::validate_pools(writer, writer).await.is_err());
    let reader_name: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(reader)
        .await?;
    let writer_name: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(writer)
        .await?;
    let quote = |name: &str| format!("\"{}\"", name.replace('"', "\"\""));
    let reader_id = quote(&reader_name);
    let writer_id = quote(&writer_name);
    let admin = test_support::test_admin_pool(reader).await?;
    let pending = fixture.create().await?;
    let request = fixture.initiate(&pending, false).await?;
    sqlx::raw_sql(&format!(
        "GRANT {writer_id} TO {reader_id} WITH INHERIT FALSE, SET TRUE"
    ))
    .execute(&admin)
    .await?;
    let inherited = database::validate_pools(reader, writer).await;
    let runtime_denial = fixture
        .send(
            "GET",
            &format!("/lti/authorize?{request}"),
            true,
            None,
            None,
        )
        .await;

    sqlx::raw_sql(&format!("REVOKE {writer_id} FROM {reader_id}"))
        .execute(&admin)
        .await?;
    assert!(
        inherited.is_err(),
        "SET-only access must not escape the read boundary"
    );
    assert_eq!(
        runtime_denial?.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the actual launch transaction must recheck changed database authority"
    );
    let restored = fixture
        .send(
            "GET",
            &format!("/lti/authorize?{request}"),
            true,
            None,
            None,
        )
        .await?;
    assert_eq!(
        restored.status(),
        StatusCode::OK,
        "authority refusal must not consume the launch"
    );
    let bridge = quote(&format!("lti_bridge_{}", Uuid::new_v4().simple()));
    sqlx::raw_sql(&format!("CREATE ROLE {bridge} NOLOGIN; GRANT {writer_id} TO {bridge} WITH INHERIT TRUE, SET FALSE; GRANT {bridge} TO {reader_id} WITH INHERIT FALSE, SET TRUE"))
        .execute(&admin).await?;
    let mixed = database::validate_pools(reader, writer).await;
    sqlx::raw_sql(&format!(
        "REVOKE {bridge} FROM {reader_id}; DROP ROLE {bridge}"
    ))
    .execute(&admin)
    .await?;
    assert!(
        mixed.is_err(),
        "SET followed by inherited write authority must be rejected"
    );
    sqlx::raw_sql(&format!(
        "GRANT UPDATE(attribute_values) ON aegaeon.user_attribute_sources TO {reader_id}"
    ))
    .execute(&admin)
    .await?;
    let column = database::validate_pools(reader, writer).await;
    sqlx::raw_sql(&format!(
        "REVOKE UPDATE(attribute_values) ON aegaeon.user_attribute_sources FROM {reader_id}"
    ))
    .execute(&admin)
    .await?;
    assert!(
        column.is_err(),
        "column grants must not escape the read boundary"
    );
    let foreign = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
        .await?;
    assert!(database::validate_pools(reader, &foreign).await.is_err());
    foreign.close().await;
    admin.close().await;
    database::validate_pools(reader, writer).await?;
    let path = fixture.create().await?;
    let request = fixture.initiate(&path, false).await?;
    let issued = fixture
        .send(
            "GET",
            &format!("/lti/authorize?{request}"),
            true,
            None,
            None,
        )
        .await?;
    assert_eq!(
        issued.status(),
        StatusCode::OK,
        "ordinary launch after restored grants"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires restricted reader/writer PostgreSQL and owned role administration"]
async fn pg_lti_management_writer_rejects_protected_authority() -> Result {
    let fixture = Fixture::new(false, false).await?;
    let reader = &fixture.state.db_pool;
    let writer = fixture.state.management.database.as_ref().ok_or("writer")?;
    let admin = test_support::test_admin_pool(reader).await?;
    let name: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(writer)
        .await?;
    let writer_id = format!("\"{}\"", name.replace('"', "\"\""));
    let role = format!("lti_privileged_{}", Uuid::new_v4().simple());
    let bridge = format!("lti_entry_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!(
        "CREATE ROLE {role} NOLOGIN; CREATE ROLE {bridge} NOLOGIN"
    ))
    .execute(&admin)
    .await?;
    let mut accepted = Vec::new();
    for (path, member, membership, removal) in [
        ("direct", writer_id.as_str(), String::new(), String::new()),
        ("inherited", role.as_str(), format!("GRANT {role} TO {writer_id} WITH INHERIT TRUE, SET FALSE"), format!("REVOKE {role} FROM {writer_id}")),
        ("set", role.as_str(), format!("GRANT {role} TO {writer_id} WITH INHERIT FALSE, SET TRUE"), format!("REVOKE {role} FROM {writer_id}")),
        ("set-then-inherit", role.as_str(), format!("GRANT {role} TO {bridge} WITH INHERIT TRUE, SET FALSE; GRANT {bridge} TO {writer_id} WITH INHERIT FALSE, SET TRUE"), format!("REVOKE {bridge} FROM {writer_id}; REVOKE {role} FROM {bridge}")),
    ] {
        if !membership.is_empty() { sqlx::raw_sql(&membership).execute(&admin).await?; }
        for privilege in [
            "SET ON PARAMETER session_replication_role",
            "UPDATE ON aegaeon.subject_ownership_namespaces",
            "INSERT(subject) ON aegaeon.end_user_subject_reservations",
            "TRIGGER ON aegaeon.lti_launch_intents",
            "UPDATE ON aegaeon.audit_events",
            "UPDATE(data) ON aegaeon.audit_events_default",
            "DELETE ON aegaeon.audit_events_default",
            "TRUNCATE ON aegaeon.audit_events_default",
            "EXECUTE ON FUNCTION aegaeon.subject_history_lock()",
            "EXECUTE ON FUNCTION aegaeon.validate_subject_ownership_namespace_v1(uuid)",
        ] {
            sqlx::raw_sql(&format!("GRANT {privilege} TO {member}")).execute(&admin).await?;
            let allowed = database::validate_pools(reader, writer).await.is_ok();
            sqlx::raw_sql(&format!("REVOKE {privilege} FROM {member}")).execute(&admin).await?;
            if allowed { accepted.push(format!("{path}: {privilege}")); }
        }
        if !removal.is_empty() { sqlx::raw_sql(&removal).execute(&admin).await?; }
    }
    sqlx::raw_sql(&format!(
        "GRANT aegaeon_subject_maintenance TO {writer_id} WITH INHERIT FALSE, SET TRUE"
    ))
    .execute(&admin)
    .await?;
    let maintenance = database::validate_pools(reader, writer).await;
    sqlx::raw_sql(&format!(
        "REVOKE aegaeon_subject_maintenance FROM {writer_id}; DROP ROLE {role}; DROP ROLE {bridge}"
    ))
    .execute(&admin)
    .await?;
    database::validate_pools(reader, writer).await?;
    sqlx::query("UPDATE aegaeon.user_attribute_sources SET revision=revision WHERE false")
        .execute(writer)
        .await?;
    admin.close().await;
    assert!(
        maintenance.is_err(),
        "maintenance authority must remain separate"
    );
    assert!(
        accepted.is_empty(),
        "unexpectedly accepted protected authority: {accepted:?}"
    );
    Ok(())
}
