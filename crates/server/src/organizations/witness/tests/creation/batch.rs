use super::*;
fn rows() -> Result<Vec<Input>> {
    (0..2)
        .map(|i| {
            Input::new(
                Kind::ManagementCsv,
                [i; 32],
                [5; 32],
                [6; 32],
                Some(&format!("csv-{i}")),
            )
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires PostgreSQL; a later-row conflict rolls back earlier-row allocation/retry in the same statement"]
async fn pg_organizations_creation_batch_prepare_atomic() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (scope,selection) = selected(&f).await?;
        let input = rows()?;
        let work = Work::begin(f.connect(Role::Runtime).await?,Local::isolated_for_test()?,scope,&selection).await?;
        for invalid in [Vec::new(),vec![input[0].clone();101],vec![input[0].clone();2]] {
            anyhow::ensure!(work.admission().prepare_creation_batch(scope.environment_id,&invalid).await.is_err());
        }
        let first = work.admission().prepare_creation_batch(scope.environment_id,&input).await?;
        let rollback = first.iter().map(|r|PrimaryOutcome::for_test(r,None)).collect::<Vec<_>>();
        work.admission().finish_creation_batch(scope.environment_id,&first,&rollback).await?;
        anyhow::ensure!(work.complete().await?.pending==0);
        let work = Work::begin(f.connect(Role::Runtime).await?,Local::isolated_for_test()?,scope,&selection).await?;
        let mut conflict = input.clone(); conflict[1]=Input::new(Kind::ManagementCsv,[1;32],[5;32],[7;32],Some("csv-1"))?;
        anyhow::ensure!(work.admission().prepare_creation_batch(scope.environment_id,&conflict).await.is_err());
        let state:Vec<(String,i32)>=sqlx::query_as("SELECT state,attempt FROM organization_witness.creations WHERE environment_id=$1 ORDER BY subject")
            .bind(scope.environment_id).fetch_all(&mut f.owner).await?;
        anyhow::ensure!(state==vec![("retryable".into(),1);2]);
        let next=work.admission().prepare_creation_batch(scope.environment_id,&input).await?;
        anyhow::ensure!(next.iter().zip(&first).all(|(a,b)|a.owner_id()==b.owner_id()&&a.attempt()==2));
        let committed=next.iter().map(|r|PrimaryOutcome::for_test(r,Some([8;32]))).collect::<Vec<_>>();
        work.admission().finish_creation_batch(scope.environment_id,&next,&committed).await?;
        anyhow::ensure!(work.complete().await?.pending==0);
        Ok(())
    }.await;
    result.and(f.finish().await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; independent batch finish failure preserves every reserved row and exact retry"]
async fn pg_organizations_creation_batch_finish_atomic() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (scope,selection)=selected(&f).await?;
        let work=Work::begin(f.connect(Role::Runtime).await?,Local::isolated_for_test()?,scope,&selection).await?;
        let receipts=work.admission().prepare_creation_batch(scope.environment_id,&rows()?).await?;
        let outcomes=receipts.iter().map(|r|PrimaryOutcome::for_test(r,Some([8;32]))).collect::<Vec<_>>();
        sqlx::raw_sql("CREATE FUNCTION organization_witness.test_batch_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.subject='csv-1' AND NEW.state='committed' THEN RAISE EXCEPTION 'injected second finish failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_batch_fault BEFORE UPDATE ON organization_witness.creations FOR EACH ROW EXECUTE FUNCTION organization_witness.test_batch_fault()")
            .execute(&mut f.owner).await?;
        let refused=work.admission().finish_creation_batch(scope.environment_id,&receipts,&outcomes).await;
        sqlx::raw_sql("DROP TRIGGER test_batch_fault ON organization_witness.creations; DROP FUNCTION organization_witness.test_batch_fault()")
            .execute(&mut f.owner).await?;
        anyhow::ensure!(refused.is_err());
        work.admission().ensure_open()?;
        let state:Vec<String>=sqlx::query_scalar("SELECT state FROM organization_witness.creations WHERE environment_id=$1 ORDER BY subject")
            .bind(scope.environment_id).fetch_all(&mut f.owner).await?;
        anyhow::ensure!(state==vec!["reserved";2]);
        let events:i64=sqlx::query_scalar("SELECT count(*) FROM organization_witness.creation_events WHERE environment_id=$1").bind(scope.environment_id).fetch_one(&mut f.owner).await?;
        anyhow::ensure!(events==2);
        work.admission().finish_creation_batch(scope.environment_id,&receipts,&outcomes).await?;
        anyhow::ensure!(work.complete().await?.pending==0);
        Ok(())
    }.await;
    result.and(f.finish().await)
}
