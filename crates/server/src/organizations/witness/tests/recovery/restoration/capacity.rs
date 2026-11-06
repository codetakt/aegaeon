use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL; concurrent last restoration slot and replay at capacity"]
async fn pg_organizations_history_restoration_capacity_race_and_replay() -> TestResult {
    let source = Source::new().await?;
    let f = Fixture::new().await?;
    let result = async {
        let fence = fence(&source);
        enroll(&f, &source, fence, true).await?;
        let mut left = f.connect(Role::Maintenance).await?;
        let mut right = f.connect(Role::Maintenance).await?;
        let mut primary = admin(&source).await?;
        let checked: TestResult = async {
            let expected = progress(&mut left, fence).await?;
            let original = Uuid::new_v4();
            let report = restore(&mut left, fence, original, &expected).await?;
            for _ in 1..15 {
                restore(&mut left, fence, Uuid::new_v4(), &expected).await?;
            }
            let first = Uuid::new_v4();
            let second = Uuid::new_v4();
            let (a, b) = tokio::join!(
                restore(&mut left, fence, first, &expected),
                restore(&mut right, fence, second, &expected)
            );
            anyhow::ensure!(
                a.is_ok() != b.is_ok(),
                "only one final operation slot can succeed"
            );
            let loser = if a.is_err() { first } else { second };
            anyhow::ensure!(pages(&mut primary, loser).await? == 0);
            let retained: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM aegaeon.subject_history_restorations WHERE environment_id=$1",
            )
            .bind(fence.scope.environment_id)
            .fetch_one(&mut primary)
            .await?;
            anyhow::ensure!(retained == 16);
            anyhow::ensure!(restore(&mut left, fence, Uuid::new_v4(), &expected)
                .await
                .is_err());
            anyhow::ensure!(
                restore(&mut left, fence, original, &expected).await? == report,
                "quota never prevents exact reconciliation"
            );
            Ok(())
        }
        .await;
        let close_left = left.close().await;
        let close_right = right.close().await;
        let close_primary = primary.close().await;
        checked?;
        close_left?;
        close_right?;
        close_primary?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; maintenance cannot multiply receipt rows using tiny or overlapping pages"]
async fn pg_organizations_history_restoration_canonical_page_budget() -> TestResult {
    let mut source = Source::new().await?;
    extend(&mut source);
    let f = Fixture::new().await?;
    let result = async {
        let fence = fence(&source);
        enroll(&f, &source, fence, true).await?;
        let mut control = f.connect(Role::Maintenance).await?;
        let (mut primary,_) = repository_tests::import::target::maintenance().await.map_err(|e|anyhow::anyhow!(e.to_string()))?;
        let checked: TestResult = async {
            let expected = progress(&mut control, fence).await?;
            let operation = Uuid::new_v4();
            for (after,limit) in [(0,1),(1,256)] {
                let page = control.history_read(fence.scope, fence.operation_id, fence.revision, after, limit).await?;
                let previous = page.entries.first().ok_or_else(||anyhow::anyhow!("entry"))?.previous_digest.clone();
                let input = json!({"operation_id":operation,"environment_id":fence.scope.environment_id,
                    "deployment_id":fence.scope.deployment_id,"witness_operation_id":fence.operation_id,
                    "witness_revision":fence.revision,"issuer_host":expected.issuer_host,
                    "source_sequence":expected.sequence,"source_digest":expected.digest,
                    "after_sequence":after,"previous_digest":previous,"entries":page.entries});
                anyhow::ensure!(sqlx::query_scalar::<_, Value>("SELECT aegaeon.restore_subject_history_page_v1($1)").bind(input).fetch_one(&mut primary).await.is_err(), "noncanonical page must refuse before any receipt");
            }
            let mut observer = admin(&source).await?;
            let absent = pages(&mut observer, operation).await? == 0;
            observer.close().await?;
            anyhow::ensure!(absent);
            restore(&mut control, fence, operation, &expected).await?;
            Ok(())
        }.await;
        let close_control = control.close().await;
        let close_primary = primary.close().await;
        checked?; close_control?; close_primary?;
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}
