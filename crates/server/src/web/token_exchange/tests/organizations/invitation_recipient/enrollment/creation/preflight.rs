use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; expiry across actual primary pool acquisition"]
async fn shared_redis_organizations_enrollment_creation_expiry_during_preflight() -> TestResult {
    let mut f = setup::new().await?;
    let previous_pool = f.state.db_pool.clone();
    let admin = crate::web::test_support::test_admin_pool(&f.base.pool).await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, Box::pin(async {
        enable(&f).await?;
        let transport = Transport::new(204,vec![],Duration::ZERO,false)?;
        let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&opened);
        let armed=Arc::new(std::sync::atomic::AtomicBool::new(false));
        let active=Arc::clone(&armed);
        f.state.db_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .before_acquire(move |_,_| {
                let observed = Arc::clone(&observed);
                let active=Arc::clone(&active);
                Box::pin(async move {
                    if active.swap(false,std::sync::atomic::Ordering::SeqCst) {
                        observed.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                    Ok(true)
                })
            })
            .connect_lazy_with((*f.base.pool.connect_options()).clone());
        f.state.validate_subject_namespace().await?;
        let value = request(&f,"registration","","pool-expiry").await?.1;
        let id = Uuid::parse_str(value["requestId"].as_str().ok_or("id")?)?;
        let expires = i64::try_from(crate::util::now_unix_epoch_secs()?)?+2;
        sqlx::query("UPDATE aegaeon.organization_identity_requests SET expires_at=$2 WHERE id=$1")
            .bind(id).bind(expires).execute(&admin).await?;
        let envelope = delivered(&f,id,&transport).await?;
        let proof = envelope["capability"].as_str().ok_or("proof")?;
        let csrf=form(&f).await?;
        armed.store(true,std::sync::atomic::Ordering::SeqCst);
        let response = post(&f,completion(id,proof,PASSWORD),Some(csrf)).await?;
        assert_ne!(response.0,StatusCode::OK);
        assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst),1);
        assert!(f.witness.creation_rows("registration").await?.is_empty(),"expired proof allocated a retained identity after pool wait");
        let count:i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1 AND email='invitee@example.test'")
            .bind(f.state.environment_id).fetch_one(&f.base.pool).await?;
        assert_eq!(count,0);
        drop(transport);Ok(())
    })).await;
    previous_pool.close().await;
    admin.close().await;
    drop(witness);
    f.finish(result).await
}
