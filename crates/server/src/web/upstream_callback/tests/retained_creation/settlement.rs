use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual independent finalization transport failure"]
async fn pg_organizations_creation_upstream_pending_refuses_existing_login() -> TestResult {
    let (f, witness) = fixture().await?;
    let admin = test_admin_pool(&f.pool).await?;
    let result = pending(&f, &witness, &admin).await;
    admin.close().await;
    finish(f, witness, result).await
}

async fn pending(f: &Fixture, witness: &CallerFixture, admin: &PgPool) -> TestResult {
    let mut barrier = admin.begin().await?;
    sqlx::query("LOCK TABLE aegaeon.end_users IN SHARE MODE")
        .execute(&mut *barrier)
        .await?;
    let work = witness.begin().await?;
    let owner = work.admission().clone();
    let label = owner.store_label()?.ok_or("work label")?.to_owned();
    let state = f.state.clone();
    let request = f.request.clone();
    let exchange = f.exchange(&request, "pending", None)?;
    let execution = tokio::spawn(async move {
        owner
            .store_scope(persist_bound_upstream_callback(
                &state,
                &request,
                &exchange,
                "pending-upstream",
            ))
            .await
    });
    let observed=tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND wait_event_type='Lock' AND query LIKE '%INSERT INTO aegaeon.end_users%')")
                .bind(&label).fetch_one(admin).await?;
            if waiting {return Ok::<_,sqlx::Error>(());}
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await;
    if !matches!(observed, Ok(Ok(()))) {
        execution.abort();
        let _ = execution.await;
        barrier.rollback().await?;
        let _ = work.complete().await;
        observed??;
        return Err("unobserved primary insert".into());
    }
    let mut independent = witness.creation_finish_barrier().await?;
    barrier.rollback().await?;
    let cut = witness.disconnect_creation_finish().await;
    let released = sqlx::query("ROLLBACK").execute(&mut independent).await;
    let closed = sqlx::Connection::close(independent).await;
    let response = tokio::time::timeout(Duration::from_secs(5), execution).await;
    let completed = work.complete().await;
    cut?;
    released?;
    closed?;
    assert!(response??.is_err() && completed.is_err());
    assert_eq!(witness.pending().await?, 1);
    let retained = witness.creation_rows("upstream").await?;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].2, "reserved");
    // Primary COMMIT really happened; this is not a pre-insert transport failure.
    assert_eq!(f.owner(&f.request, "pending").await?.0, retained[0].0);
    run(witness, async {
        let mut request = f.request.clone();
        request.state = "fresh-after-uncertain-commit".into();
        f.rejected(&request, "pending", None).await?;
        assert_eq!(witness.creation_rows("upstream").await?, retained);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; independent committed record cannot hide missing primary receipt"]
async fn pg_organizations_creation_upstream_missing_primary_receipt_refuses() -> TestResult {
    let (f, witness) = fixture().await?;
    let admin = test_admin_pool(&f.pool).await?;
    let result=async {
        run(&witness,async {f.success_subject(f.callback(&f.request,"missing-receipt",None).await?).await?;Ok(())}).await?;
        let owner=f.owner(&f.request,"missing-receipt").await?.0;
        let mut tx=admin.begin().await?;
        sqlx::query("SET LOCAL session_replication_role='replica'").execute(&mut *tx).await?;
        let changed=sqlx::query("DELETE FROM aegaeon.organization_creation_receipts WHERE environment_id=$1 AND owner_id=$2").bind(f.env.environment_id).bind(owner).execute(&mut *tx).await?;
        assert_eq!(changed.rows_affected(),1);tx.commit().await?;
        run(&witness,async {f.rejected(&f.request,"missing-receipt",None).await}).await
    }.await;
    admin.close().await;
    finish(f, witness, result).await
}
