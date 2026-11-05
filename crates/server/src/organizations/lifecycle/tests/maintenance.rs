use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_lifecycle_offline_maintenance_excludes_runtime_and_checks_selection(
) -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let runtime = f.pool(f.selected);
    let connection = runtime.acquire().await?;
    let mut operator = PgConnection::connect_with(f.database.connect_options().as_ref()).await?;
    assert!(f.selected.bind_maintenance(&mut operator).await.is_err());
    drop(connection);
    runtime.close().await;
    wait_runtime_release(&f.database).await?;
    f.selected.bind_maintenance(&mut operator).await?;
    let reopened = f.pool(f.selected);
    assert!(reopened.acquire().await.is_err());
    let tx = operator.begin().await?;
    tx.rollback().await?;
    assert!(
        reopened.acquire().await.is_err(),
        "maintenance lock survives transaction rollback"
    );
    operator.close().await?;
    wait_runtime_release(&f.database).await?;
    let value = reopened.acquire().await?;
    drop(value);
    reopened.close().await;
    wait_runtime_release(&f.database).await?;
    let mut wrong = PgConnection::connect_with(f.database.connect_options().as_ref()).await?;
    assert!(Selection::new(f.selected.deployment_id(), Uuid::new_v4())?
        .bind_maintenance(&mut wrong)
        .await
        .is_err());
    wrong.close().await?;
    wait_runtime_release(&f.database).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon_lifecycle.activations")
        .fetch_one(&f.database)
        .await?;
    assert_eq!(
        count, 1,
        "offline maintenance does not create a generation or replay history"
    );
    f.finish().await
}
