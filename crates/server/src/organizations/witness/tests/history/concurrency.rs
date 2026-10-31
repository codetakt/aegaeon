use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; competing subject and global owner reservations"]
async fn pg_organizations_history_concurrent_reservations_are_atomic() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = concurrent(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}
async fn concurrent(f: &mut Fixture) -> TestResult {
    let scope = scope();
    let plan = plan(scope, &[])?;
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let operation = enrolled(&mut maintenance, scope, &plan).await?;
    let selected = activated(&mut maintenance, scope, operation, &plan).await?;
    let mut first = f.connect(Role::Runtime).await?;
    let mut second = f.connect(Role::Runtime).await?;
    let first_admission = first.acquire(scope, &selected, Uuid::new_v4()).await?;
    let second_admission = second.acquire(scope, &selected, Uuid::new_v4()).await?;
    let first_owner = Uuid::new_v4();
    let second_owner = Uuid::new_v4();
    let (a, b) = tokio::join!(
        first.history_reserve(&first_admission, first_owner, "race"),
        second.history_reserve(&second_admission, second_owner, "race")
    );
    anyhow::ensure!(a.is_ok() != b.is_ok(), "only one subject owner may win");
    let winner = if a.is_ok() { first_owner } else { second_owner };
    let retained = first
        .history_check(&first_admission, winner, "race")
        .await?;
    anyhow::ensure!(
        retained.sequence == 2 && retained.owner_count == 1 && retained.subject_count == 1,
        "losing owner insertion must roll back"
    );
    let (a, b) = tokio::join!(
        first.history_reserve(&first_admission, winner, "race"),
        second.history_reserve(&second_admission, winner, "race")
    );
    anyhow::ensure!(
        a?.digest == retained.digest && b?.digest == retained.digest,
        "exact concurrent replay must not advance history"
    );
    first.complete(&first_admission).await?;
    second.complete(&second_admission).await?;

    let other_scope = super::scope();
    let other_plan = super::plan(other_scope, &[])?;
    let other_operation = enrolled(&mut maintenance, other_scope, &other_plan).await?;
    let other_selected =
        activated(&mut maintenance, other_scope, other_operation, &other_plan).await?;
    let first_admission = first.acquire(scope, &selected, Uuid::new_v4()).await?;
    let second_admission = second
        .acquire(other_scope, &other_selected, Uuid::new_v4())
        .await?;
    let global_owner = Uuid::new_v4();
    let (a, b) = tokio::join!(
        first.history_reserve(&first_admission, global_owner, "global"),
        second.history_reserve(&second_admission, global_owner, "global")
    );
    anyhow::ensure!(
        a.is_ok() != b.is_ok(),
        "one global owner must never bind two Environments"
    );
    let first_won = a.is_ok();
    first.complete(&first_admission).await?;
    second.complete(&second_admission).await?;
    let first_fence = maintenance.fence(scope, Uuid::new_v4(), 3).await?;
    let second_fence = maintenance.fence(other_scope, Uuid::new_v4(), 3).await?;
    let a = maintenance
        .history_read(
            scope,
            first_fence.operation_id,
            first_fence.revision,
            0,
            256,
        )
        .await?;
    let b = maintenance
        .history_read(
            other_scope,
            second_fence.operation_id,
            second_fence.revision,
            0,
            256,
        )
        .await?;
    anyhow::ensure!(a.progress.sequence == if first_won { 4 } else { 2 });
    anyhow::ensure!(b.progress.sequence == if first_won { 0 } else { 2 });
    first.close().await?;
    second.close().await?;
    maintenance.close().await?;
    Ok(())
}
