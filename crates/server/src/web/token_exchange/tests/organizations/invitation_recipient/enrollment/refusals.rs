use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn shared_redis_organizations_enrollment_outbox_failure_rolls_back_identity_and_recovers(
) -> TestResult {
    let f = setup::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.base.pool).await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, Box::pin(async {
        enable(&f).await?;
        let transport = Transport::new(204,vec![],Duration::ZERO,false)?;
        let value = request(&f,"registration","","failure").await?.1;
        let id = Uuid::parse_str(value["requestId"].as_str().ok_or("id")?)?;
        let envelope = delivered(&f,id,&transport).await?;
        let proof = envelope["capability"].as_str().ok_or("proof")?;
        let constraint = format!("enrollment_fixture_{}",Uuid::new_v4().simple());
        sqlx::query(&format!("ALTER TABLE aegaeon.organization_authority_outbox ADD CONSTRAINT {constraint} CHECK (attempts < 0) NOT VALID")).execute(&admin).await?;
        let failed = post(&f,completion(id,proof,PASSWORD),None).await;
        sqlx::query(&format!("ALTER TABLE aegaeon.organization_authority_outbox DROP CONSTRAINT {constraint}")).execute(&admin).await?;
        assert_eq!(failed?.0,StatusCode::SERVICE_UNAVAILABLE);
        let state: String = sqlx::query_scalar("SELECT state FROM aegaeon.organization_identity_requests WHERE id=$1").bind(id).fetch_one(&f.base.pool).await?;
        assert_eq!(state,"pending");
        let count:i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1 AND email='invitee@example.test'").bind(f.state.environment_id).fetch_one(&f.base.pool).await?;
        assert_eq!(count,0);
        assert_eq!(post(&f,completion(id,proof,PASSWORD),None).await?.0,StatusCode::OK);
        drop(transport);Ok(())
    })).await;
    admin.close().await;
    drop(witness);
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn shared_redis_organizations_enrollment_finite_requests_and_unverified_recovery_refuse(
) -> TestResult {
    let f = setup::new().await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, Box::pin(async {
        enable(&f).await?;
        let transport = Transport::new(204,vec![],Duration::ZERO,false)?;
        let user = f.base.users[0];
        sqlx::query("UPDATE aegaeon.end_users SET email='invitee@example.test' WHERE id=$1").bind(user).execute(&f.base.pool).await?;
        sqlx::query("INSERT INTO aegaeon.end_user_profiles(end_user_id,email_verified) VALUES ($1,true) ON CONFLICT(end_user_id) DO UPDATE SET email_verified=true").bind(user).execute(&f.base.pool).await?;
        sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash) VALUES ($1,$2) ON CONFLICT(end_user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash")
            .bind(user).bind(crate::local_credentials::hash_password(PASSWORD)?).execute(&f.base.pool).await?;
        let subject: String = sqlx::query_scalar("SELECT subject FROM aegaeon.end_users WHERE id=$1").bind(user).fetch_one(&f.base.pool).await?;
        let mut first = None;
        for index in 0..5 {
            let (status,value) = request(&f,"password_recovery",&subject,&format!("bounded-{index}")).await?;
            assert_eq!(status,StatusCode::OK,"{value}");
            let id = Uuid::parse_str(value["requestId"].as_str().ok_or("id")?)?;
            if index == 0 { first = Some(id); }
        }
        assert_eq!(request(&f,"password_recovery",&subject,"sixth").await?.0,StatusCode::CONFLICT);
        let id = first.ok_or("request")?;
        let envelope = delivered(&f,id,&transport).await?;
        // Only lowercase legacy email is verified. The invitation proves the
        // different uppercase local part; it must not recover this account.
        assert_ne!(post(&f,completion(id,envelope["capability"].as_str().ok_or("proof")?,"unexpected-new-password"),None).await?.0,StatusCode::OK);
        assert!(crate::local_credentials::authenticate_local_user(&f.base.pool,&f.state.issuer,&subject,PASSWORD).await?.is_some());
        let target:Option<Uuid> = sqlx::query_scalar("SELECT target_user_id FROM aegaeon.organization_identity_requests WHERE id=$1").bind(id).fetch_one(&f.base.pool).await?;
        assert!(target.is_none());
        drop(transport);Ok(())
    })).await;
    drop(witness);
    f.finish(result).await
}
