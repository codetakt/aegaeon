use super::*;
mod preflight;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn shared_redis_organizations_enrollment_creation_authentication_precedes_allocation(
) -> TestResult {
    let f = setup::new().await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, Box::pin(async {
        enable(&f).await?;
        let transport = Transport::new(204,vec![],Duration::ZERO,false)?;
        let value = request(&f,"registration","","retained").await?.1;
        let id = Uuid::parse_str(value["requestId"].as_str().ok_or("id")?)?;
        let envelope = delivered(&f,id,&transport).await?;
        let proof = envelope["capability"].as_str().ok_or("proof")?;
        let mut mismatch = completion(id,proof,PASSWORD);
        mismatch.last_mut().ok_or("confirmation")?.1="different".into();
        for fields in [mismatch,completion(id,&f.capability,PASSWORD),completion(Uuid::new_v4(),proof,PASSWORD),completion(id,proof,"")] {
            assert_ne!(post(&f,fields,None).await?.0,StatusCode::OK);
            assert!(f.witness.creation_rows("registration").await?.is_empty());
        }
        let response=post(&f,completion(id,proof,PASSWORD),None).await?;
        assert_eq!(response.0,StatusCode::OK,"{}",response.1);
        let rows=f.witness.creation_rows("registration").await?;
        assert_eq!(rows.len(),1);
        assert_eq!(rows[0].1,rows[0].0.to_string());
        assert_eq!(response.1["subject"],rows[0].1);
        assert_eq!((&*rows[0].2,rows[0].3),("committed",1));
        let receipt:(Uuid,String)=sqlx::query_as("SELECT owner_id,subject FROM aegaeon.organization_creation_receipts WHERE environment_id=$1 AND kind='registration'")
            .bind(f.state.environment_id).fetch_one(&f.base.pool).await?;
        assert_eq!(receipt,(rows[0].0,rows[0].1.clone()));
        assert_eq!(post(&f,completion(id,proof,PASSWORD),None).await?.0,StatusCode::OK);
        assert_eq!(f.witness.creation_rows("registration").await?,rows);
        sqlx::query("UPDATE aegaeon.end_users SET status='DELETED' WHERE id=$1").bind(rows[0].0).execute(&f.base.pool).await?;
        assert_ne!(post(&f,completion(id,proof,PASSWORD),None).await?.0,StatusCode::OK);
        assert_eq!(f.witness.creation_rows("registration").await?,rows);
        drop(transport);Ok(())
    })).await;
    drop(witness);
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn shared_redis_organizations_enrollment_creation_reauthorizes_after_reservation(
) -> TestResult {
    let f = setup::new().await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(
        &witness,
        Box::pin(async {
            enable(&f).await?;
            let transport = Transport::new(204, vec![], Duration::ZERO, false)?;
            let value = request(&f, "registration", "", "revoked").await?.1;
            let id = Uuid::parse_str(value["requestId"].as_str().ok_or("id")?)?;
            let envelope = delivered(&f, id, &transport).await?;
            let proof = envelope["capability"].as_str().ok_or("proof")?;
            let mut barrier = f.witness.history_append_barrier().await?;
            let controller = async {
                let observed = f.witness.wait_for_creation_prepare().await;
                let revoked = sqlx::query(
                    "UPDATE aegaeon.environments SET organization_identity_policy=NULL WHERE id=$1",
                )
                .bind(f.state.environment_id)
                .execute(&f.base.pool)
                .await;
                let released = sqlx::query("ROLLBACK").execute(&mut barrier).await;
                let closed = sqlx::Connection::close(barrier).await;
                observed?;
                revoked?;
                released?;
                closed?;
                Ok::<(), Box<dyn std::error::Error>>(())
            };
            let (response, controlled) =
                tokio::join!(post(&f, completion(id, proof, PASSWORD), None), controller);
            controlled?;
            assert_ne!(response?.0, StatusCode::OK);
            let rows = f.witness.creation_rows("registration").await?;
            assert_eq!(rows.len(), 1);
            assert_eq!((&*rows[0].2, rows[0].3), ("retryable", 1));
            let count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM aegaeon.end_users WHERE id=$1")
                    .bind(rows[0].0)
                    .fetch_one(&f.base.pool)
                    .await?;
            assert_eq!(count, 0);
            drop(transport);
            Ok(())
        }),
    )
    .await;
    drop(witness);
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; real expiry during primary receipt statement"]
async fn shared_redis_organizations_enrollment_creation_expiry_before_commit() -> TestResult {
    let f = setup::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.base.pool).await?;
    let witness = Arc::clone(&f.witness);
    let result=in_epoch(&witness,Box::pin(async {
        enable(&f).await?;
        let transport=Transport::new(204,vec![],Duration::ZERO,false)?;
        let value=request(&f,"registration","","expires").await?.1;
        let id=Uuid::parse_str(value["requestId"].as_str().ok_or("id")?)?;
        let expires=i64::try_from(crate::util::now_unix_epoch_secs()?)?+2;
        sqlx::query("UPDATE aegaeon.organization_identity_requests SET expires_at=$2 WHERE id=$1")
            .bind(id).bind(expires).execute(&admin).await?;
        let envelope=delivered(&f,id,&transport).await?;
        let proof=envelope["capability"].as_str().ok_or("proof")?;
        let name=format!("registration_delay_{}",Uuid::new_v4().simple());
        sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id='{}'::uuid THEN PERFORM pg_sleep(3); END IF; RETURN NEW; END $$; CREATE TRIGGER {name} AFTER INSERT ON aegaeon.organization_creation_receipts FOR EACH ROW EXECUTE FUNCTION aegaeon.{name}()",f.state.environment_id)).execute(&admin).await?;
        let owner=crate::organizations::request_work::async_store::current_epoch_owner(f.state.environment_id)?;
        let label=owner.store_label()?.ok_or("work label")?.to_owned();
        let controller=tokio::time::timeout(Duration::from_secs(3),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event='PgSleep' AND query LIKE '%organization_creation_record_v1%')")
                    .bind(&label).fetch_one(&admin).await?;
                if waiting { return Ok::<(),sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let (response,observed)=tokio::join!(post(&f,completion(id,proof,PASSWORD),None),controller);
        let cleanup=sqlx::raw_sql(&format!("DROP TRIGGER {name} ON aegaeon.organization_creation_receipts; DROP FUNCTION aegaeon.{name}()")).execute(&admin).await;
        cleanup?;observed??;
        assert_ne!(response?.0,StatusCode::OK,"expired proof committed after receipt wait");
        let rows=f.witness.creation_rows("registration").await?;
        assert_eq!(rows.len(),1);assert_eq!((&*rows[0].2,rows[0].3),("retryable",1));
        let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.end_users WHERE id=$1),(SELECT count(*) FROM aegaeon.organization_creation_receipts WHERE owner_id=$1)")
            .bind(rows[0].0).fetch_one(&f.base.pool).await?;
        assert_eq!(counts,(0,0));
        drop(transport);Ok(())
    })).await;
    admin.close().await;
    drop(witness);
    f.finish(result).await
}
