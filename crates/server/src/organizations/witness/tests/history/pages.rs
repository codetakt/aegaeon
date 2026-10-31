use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; maximum history pages, raw overrun and digest corruption"]
async fn pg_organizations_history_page_boundaries_and_digest() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = pages(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}
async fn pages(f: &mut Fixture) -> TestResult {
    let scope = scope();
    let operation = Uuid::new_v4();
    let owners = (0..257)
        .map(|id| (Uuid::from_u128(id), vec![]))
        .collect::<Vec<_>>();
    let plan = plan(scope, &owners)?;
    let entries = plan.batches().flatten().cloned().collect::<Vec<_>>();
    let mut maintenance = f.connect(Role::Maintenance).await?;
    maintenance.initialize(scope, operation).await?;
    maintenance
        .history_begin(scope, operation, 1, &plan)
        .await?;
    anyhow::ensure!(maintenance
        .history_batch(scope, operation, 1, 0, &entries)
        .await
        .is_err());
    let encoded = serde_json::to_value(&entries)?;
    anyhow::ensure!(
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT organization_witness.history_batch($1,$2,$3,1,0,$4)"
        )
        .bind(scope.environment_id)
        .bind(scope.deployment_id)
        .bind(operation)
        .bind(encoded)
        .fetch_one(maintenance.connection.as_mut().unwrap())
        .await
        .is_err(),
        "actual SQL must reject 257 entries"
    );
    anyhow::ensure!(
        maintenance
            .history_read(scope, operation, 1, 0, 256)
            .await?
            .progress
            .sequence
            == 0
    );
    maintenance
        .history_batch(scope, operation, 1, 0, &entries[..256])
        .await?;
    maintenance
        .history_batch(scope, operation, 1, 256, &entries[256..])
        .await?;
    anyhow::ensure!(maintenance.history_seal(scope, operation, 1).await?.digest == plan.digest());
    let first = maintenance
        .history_read(scope, operation, 1, 0, 256)
        .await?;
    let second = maintenance
        .history_read(scope, operation, 1, 256, 256)
        .await?;
    anyhow::ensure!(first.entries.len() == 256 && second.entries.len() == 1);
    anyhow::ensure!(first.entries[255].digest == second.entries[0].previous_digest);
    anyhow::ensure!(maintenance
        .history_read(scope, operation, 1, 257, 256)
        .await?
        .entries
        .is_empty());
    anyhow::ensure!(maintenance
        .history_read(scope, operation, 1, 258, 256)
        .await
        .is_err());

    // Deliberate administrator corruption is separate from service authority.
    // A complete catalog alone must not make inconsistent retained data valid.
    let before:Vec<u8>=sqlx::query_scalar("SELECT digest FROM organization_witness.history_entries WHERE environment_id=$1 AND sequence=1")
        .bind(scope.environment_id).fetch_one(&mut f.owner).await?;
    sqlx::query("UPDATE organization_witness.history_entries SET digest=decode(repeat('00',32),'hex') WHERE environment_id=$1 AND sequence=1")
        .bind(scope.environment_id).execute(&mut f.owner).await?;
    anyhow::ensure!(
        maintenance
            .history_read(scope, operation, 1, 0, 256)
            .await
            .is_err(),
        "inconsistent digest chain must refuse"
    );
    sqlx::query("UPDATE organization_witness.history_entries SET digest=$2 WHERE environment_id=$1 AND sequence=1")
        .bind(scope.environment_id).bind(before).execute(&mut f.owner).await?;
    anyhow::ensure!(
        maintenance
            .history_read(scope, operation, 1, 0, 256)
            .await?
            .entries
            .len()
            == 256
    );
    maintenance.close().await?;
    Ok(())
}
