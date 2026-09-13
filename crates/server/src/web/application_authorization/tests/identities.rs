use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_application_client_record_reuse_and_identity_mismatch_fail_closed() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let other = setup_test_environment(&pool).await?;
    let result = async {
        let claims = json!({"roles":[],"organization_roles":[]});
        let (client, user) = seed_test_projection(&pool,&env,"service","service",json!(["resource"]),claims.clone()).await?;
        assert!(user.is_none());
        let (foreign, _) = seed_test_projection(&pool,&other,"service","service",json!(["resource"]),claims).await?;
        let original = capture(&pool,env.environment_id,&env.issuer_url,"service","service").await?.ok_or("service grant")?;
        assert!(lock_current(&pool,env.environment_id,&env.issuer_url,&original).await?.is_some());
        sqlx::query("UPDATE aegaeon.application_authorizations SET client_record_id=$2 WHERE environment_id=$1")
            .bind(env.environment_id).bind(foreign).execute(&pool).await?;
        assert!(capture(&pool,env.environment_id,&env.issuer_url,"service","service").await?.is_none());
        assert!(lock_current(&pool,env.environment_id,&env.issuer_url,&original).await?.is_none());
        sqlx::query("UPDATE aegaeon.application_authorizations SET client_record_id=$2 WHERE environment_id=$1")
            .bind(env.environment_id).bind(client).execute(&pool).await?;
        // Low-level identifier reuse is permitted by the persistence schema;
        // current management/DCR create APIs generate identifiers themselves.
        sqlx::query("UPDATE aegaeon.clients SET status='DELETED',deleted_at=now() WHERE id=$1")
            .bind(client).execute(&pool).await?;
        assert!(capture(&pool,env.environment_id,&env.issuer_url,"service","service").await?.is_none());
        assert!(lock_current(&pool,env.environment_id,&env.issuer_url,&original).await?.is_none());
        let recreated: Uuid = sqlx::query_scalar("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,status) SELECT environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,'ACTIVE' FROM aegaeon.clients WHERE id=$1 RETURNING id")
            .bind(client).fetch_one(&pool).await?;
        assert_ne!(recreated, client);
        assert!(capture(&pool,env.environment_id,&env.issuer_url,"service","service").await?.is_none());
        assert!(!is_current(&pool,env.environment_id,&env.issuer_url,&original).await?);
        assert!(lock_current(&pool,env.environment_id,&env.issuer_url,&original).await?.is_none());
        // Physical cleanup keeps the revision tombstone, with no inferred owner.
        sqlx::query("DELETE FROM aegaeon.clients WHERE id=$1").bind(client).execute(&pool).await?;
        let retained: (i64, Option<Uuid>) = sqlx::query_as("SELECT revision,client_record_id FROM aegaeon.application_authorizations WHERE environment_id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(retained, (1, None));
        assert!(capture(&pool,env.environment_id,&env.issuer_url,"service","service").await?.is_none());
        assert!(is_current(&pool,other.environment_id,&other.issuer_url,
            &capture(&pool,other.environment_id,&other.issuer_url,"service","service").await?.ok_or("control grant")?).await?);
        Ok(())
    }.await;
    let result = finish_test(result, cleanup_test_environment(&pool, &other).await);
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_application_publication_holds_client_and_user_identity_locks() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        seed_test_projection(&pool,&env,"client","subject",json!(["resource"]),json!({"roles":["USER"],"organization_roles":[]})).await?;
        let grant = capture(&pool,env.environment_id,&env.issuer_url,"client","subject").await?.ok_or("grant")?;
        for update in [
            "UPDATE aegaeon.clients SET status='DELETED',deleted_at=now() WHERE environment_id=$1",
            "UPDATE aegaeon.end_users SET subject='renamed' WHERE environment_id=$1",
        ] {
            let guard = lock_current(&pool,env.environment_id,&env.issuer_url,&grant).await?.ok_or("publication guard")?;
            let mut blocked = pool.begin().await?;
            sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *blocked).await?;
            let error = sqlx::query(update).bind(env.environment_id).execute(&mut *blocked).await.expect_err("identity update must wait");
            assert_eq!(error.as_database_error().and_then(|e| e.code()).as_deref(), Some("55P03"));
            blocked.rollback().await?;
            guard.commit().await?;
            let mut allowed = pool.begin().await?;
            sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *allowed).await?;
            assert_eq!(sqlx::query(update).bind(env.environment_id).execute(&mut *allowed).await?.rows_affected(), 1);
            allowed.rollback().await?;
            assert!(is_current(&pool,env.environment_id,&env.issuer_url,&grant).await?);
        }
        let user: Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.end_users WHERE environment_id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        sqlx::query("DELETE FROM aegaeon.end_users WHERE id=$1").bind(user).execute(&pool).await?;
        let retained: (i64, Option<Uuid>) = sqlx::query_as("SELECT revision,end_user_record_id FROM aegaeon.application_authorizations WHERE environment_id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(retained, (1, None));
        assert!(capture(&pool,env.environment_id,&env.issuer_url,"client","subject").await?.is_none());
        assert!(lock_current(&pool,env.environment_id,&env.issuer_url,&grant).await?.is_none());
        Ok(())
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
