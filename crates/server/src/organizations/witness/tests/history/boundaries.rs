use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual history role and catalog boundaries"]
async fn pg_organizations_history_privileges_and_catalog_refuse() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = boundaries(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}
async fn boundaries(f: &mut Fixture) -> TestResult {
    let scope = scope();
    let plan = plan(scope, &[])?;
    let operation = Uuid::new_v4();
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let mut runtime = f.connect(Role::Runtime).await?;
    maintenance.initialize(scope, operation).await?;
    anyhow::ensure!(runtime
        .history_begin(scope, operation, 1, &plan)
        .await
        .is_err());
    maintenance
        .history_begin(scope, operation, 1, &plan)
        .await?;
    anyhow::ensure!(maintenance
        .history_read(scope, Uuid::new_v4(), 1, 0, 1)
        .await
        .is_err());
    anyhow::ensure!(maintenance
        .history_read(
            Scope {
                deployment_id: Uuid::new_v4(),
                ..scope
            },
            operation,
            1,
            0,
            1
        )
        .await
        .is_err());
    anyhow::ensure!(maintenance
        .history_read(scope, operation, 1, 0, 257)
        .await
        .is_err());
    anyhow::ensure!(runtime
        .history_read(scope, operation, 1, 0, 1)
        .await
        .is_err());
    // Call PostgreSQL directly so wrapper-only role checks cannot satisfy this.
    for query in [
        "SELECT organization_witness.history_progress(gen_random_uuid())",
        "SELECT organization_witness.history_append(gen_random_uuid(),0::smallint,gen_random_uuid(),NULL,NULL,NULL,NULL,NULL)",
        "SELECT organization_witness.history_seal(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1)",
        "SELECT organization_witness.history_read(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1,0,1)",
        "SELECT * FROM organization_witness.history_namespaces",
        "DELETE FROM organization_witness.history_entries",
        "TRUNCATE organization_witness.history_owners CASCADE",
        "UPDATE organization_witness.history_namespaces SET sealed=true",
        "SET ROLE aegaeon_organization_witness_owner",
    ] {
        anyhow::ensure!(sqlx::query(query).execute(runtime.connection.as_mut().unwrap()).await.is_err(),"runtime history privilege escaped");
    }
    anyhow::ensure!(sqlx::query("SELECT organization_witness.history_reserve(gen_random_uuid(),gen_random_uuid(),0,1,gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'A')").execute(maintenance.connection.as_mut().unwrap()).await.is_err());
    // Even a valid control admission cannot use an incomplete history namespace.
    let selection = activated(&mut maintenance, scope, operation, &plan).await?;
    let admission = runtime.acquire(scope, &selection, Uuid::new_v4()).await?;
    anyhow::ensure!(runtime
        .history_reserve(&admission, Uuid::new_v4(), "A")
        .await
        .is_err());
    let fenced = maintenance.fence(scope, Uuid::new_v4(), 3).await?;
    anyhow::ensure!(
        maintenance
            .history_read(scope, fenced.operation_id, fenced.revision, 0, 1)
            .await
            .is_err(),
        "pending work must prevent history inspection"
    );
    runtime.complete(&admission).await?;
    runtime.close().await?;
    maintenance.close().await?;

    sqlx::raw_sql("ALTER TABLE organization_witness.history_namespaces ALTER COLUMN issuer_host TYPE text COLLATE \"default\"").execute(&mut f.owner).await?;
    let accepted = f.connect(Role::Runtime).await;
    if let Ok(control) = accepted {
        control.close().await?;
        anyhow::bail!("history collation drift accepted");
    }
    sqlx::raw_sql("ALTER TABLE organization_witness.history_namespaces ALTER COLUMN issuer_host TYPE text COLLATE \"C\"").execute(&mut f.owner).await?;
    f.connect(Role::Runtime).await?.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; durable history survives owner disconnect and binds principal"]
async fn pg_organizations_history_principal_and_disconnect() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let role = format!("history_other_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::raw_sql(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{password}' IN ROLE aegaeon_organization_witness_runtime"
    ))
    .execute(&mut fixture.owner)
    .await?;
    let result = principal(&mut fixture, &role, &password).await;
    let remove = sqlx::raw_sql(&format!("DROP ROLE {role}"))
        .execute(&mut fixture.owner)
        .await
        .map(|_| ())
        .map_err(Into::into);
    let cleanup = fixture.finish().await;
    result.and(remove).and(cleanup)
}
async fn principal(f: &mut Fixture, role: &str, password: &str) -> TestResult {
    let scope = scope();
    let plan = plan(scope, &[])?;
    let owner = Uuid::new_v4();
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let operation = enrolled(&mut maintenance, scope, &plan).await?;
    let selection = activated(&mut maintenance, scope, operation, &plan).await?;
    let mut runtime = f.connect(Role::Runtime).await?;
    let admission = runtime.acquire(scope, &selection, Uuid::new_v4()).await?;
    let appended = runtime.history_reserve(&admission, owner, "A").await?;
    anyhow::ensure!(appended.sequence == 2);
    runtime.close().await?; // The independent reservation and pending owner remain.
    anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
    let connection =
        PgConnection::connect_with(&f.options.clone().username(role).password(password)).await?;
    let mut other = Control::checked(connection, Role::Runtime).await?;
    anyhow::ensure!(other.history_check(&admission, owner, "A").await.is_err());
    anyhow::ensure!(other.history_reserve(&admission, owner, "B").await.is_err());
    other.close().await?;
    let mut recovered = f.connect(Role::Runtime).await?;
    anyhow::ensure!(
        recovered
            .history_check(&admission, owner, "A")
            .await?
            .digest
            == appended.digest
    );
    anyhow::ensure!(
        recovered
            .history_reserve(&admission, owner, "A")
            .await?
            .sequence
            == 2
    );
    recovered.complete(&admission).await?;
    recovered.close().await?;
    maintenance.close().await?;
    Ok(())
}
