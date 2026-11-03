use super::*;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL principals and owned role administration"]
async fn pg_lti_reader_admin_option_refuses_self_grants_and_preserves_intent() -> Result {
    administration(false).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL principals and owned role administration"]
async fn pg_lti_writer_admin_option_refuses_self_grants_over_audit_history() -> Result {
    administration(true).await
}

async fn administration(management: bool) -> Result {
    let fixture = Fixture::new(false, false).await?;
    let reader = &fixture.state.db_pool;
    let writer = fixture.state.management.database.as_ref().ok_or("writer")?;
    let actor = if management { writer } else { reader };
    let admin = test_support::test_admin_pool(reader).await?;
    let name: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(actor)
        .await?;
    let quoted = format!("\"{}\"", name.replace('"', "\"\""));
    let target = format!("lti_admin_target_{}", Uuid::new_v4().simple());
    let bridge = format!("lti_admin_bridge_{}", Uuid::new_v4().simple());
    let relation = if management {
        "aegaeon.audit_events_default"
    } else {
        "aegaeon.user_attribute_sources"
    };
    sqlx::raw_sql(&format!("CREATE ROLE {target} NOLOGIN; CREATE ROLE {bridge} NOLOGIN; GRANT USAGE ON SCHEMA aegaeon TO {target}; GRANT UPDATE ON {relation} TO {target}"))
        .execute(&admin).await?;
    let forbidden = format!(
        "UPDATE {relation} SET {} = {} WHERE false",
        if management { "data" } else { "revision" },
        if management { "data" } else { "revision" }
    );
    let pending = fixture.create().await?;
    let request = fixture.initiate(&pending, false).await?;
    let mut accepted = Vec::new();
    for (path, membership, removal, effective_admin) in [
        ("direct", format!("GRANT {target} TO {quoted} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"), format!("REVOKE {target} FROM {quoted} CASCADE"), None),
        ("set", format!("GRANT {target} TO {bridge} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT {bridge} TO {quoted} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"), format!("REVOKE {bridge} FROM {quoted}; REVOKE {target} FROM {bridge} CASCADE"), Some(bridge.as_str())),
        ("inherit", format!("GRANT {target} TO {bridge} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT {bridge} TO {quoted} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"), format!("REVOKE {bridge} FROM {quoted}; REVOKE {target} FROM {bridge} CASCADE"), None),
        ("membership", format!("GRANT {target} TO {bridge} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT {bridge} TO {quoted} WITH ADMIN FALSE, INHERIT FALSE, SET FALSE"), format!("REVOKE {bridge} FROM {quoted}; REVOKE {target} FROM {bridge} CASCADE"), None),
    ] {
        sqlx::raw_sql(&membership).execute(&admin).await?;
        // The serving login cannot use the privilege yet and has no CREATEROLE.
        assert!(!sqlx::query_scalar::<_, bool>("SELECT rolcreaterole FROM pg_roles WHERE rolname=current_user").fetch_one(actor).await?);
        assert!(sqlx::query(&forbidden).execute(actor).await.is_err());
        let allowed = database::validate_pools(reader, writer).await.is_ok();
        let response = if management { None } else {
            Some(fixture.send("GET", &format!("/lti/authorize?{request}"), true, None, None).await?)
        };
        if path == "direct" || path == "set" {
            // Demonstrate actual privilege acquisition as the serving principal.
            // Roll back its self-grant; no protected row is changed.
            let mut tx = actor.begin().await?;
            if let Some(role) = effective_admin {
                sqlx::raw_sql(&format!("SET LOCAL ROLE {role}")).execute(&mut *tx).await?;
            }
            sqlx::raw_sql(&format!("GRANT {target} TO {quoted} WITH INHERIT TRUE, SET TRUE")).execute(&mut *tx).await?;
            sqlx::raw_sql("RESET ROLE").execute(&mut *tx).await?;
            sqlx::query(&forbidden).execute(&mut *tx).await?;
            tx.rollback().await?;
        }
        sqlx::raw_sql(&removal).execute(&admin).await?;
        if allowed { accepted.push(path); }
        if let Some(response) = response {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}: live reader check");
        }
        database::validate_pools(reader, writer).await?;
    }
    // A membership without ADMIN, INHERIT or SET authority remains harmless.
    sqlx::raw_sql(&format!(
        "GRANT {target} TO {quoted} WITH ADMIN FALSE, INHERIT FALSE, SET FALSE"
    ))
    .execute(&admin)
    .await?;
    database::validate_pools(reader, writer).await?;
    sqlx::raw_sql(&format!("REVOKE {target} FROM {quoted}; DROP OWNED BY {target}; DROP ROLE {target}; DROP ROLE {bridge}"))
        .execute(&admin).await?;
    admin.close().await;
    assert!(
        accepted.is_empty(),
        "administrative memberships accepted: {accepted:?}"
    );
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
