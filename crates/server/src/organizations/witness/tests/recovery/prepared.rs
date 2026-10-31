use super::*;
use crate::organizations::repository_tests::import::inactive;
use serde_json::json;

async fn prepared() -> anyhow::Result<(Source, Uuid)> {
    let mut source = Source::new().await?;
    let (bytes, scope) = inactive::prospective(&source.fixture)
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    source.bytes = bytes;
    source.scope = scope;
    let operation = Uuid::new_v4();
    inactive::prepare(&source.bytes, scope, operation)
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok((source, operation))
}
async fn check(
    source: &Source,
    control: Control,
    fence: recovery::Fence,
    operation: Uuid,
) -> anyhow::Result<Value> {
    let (connection, runtime) = repository_tests::import::target::maintenance()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let input = Input::new(
        Cursor::new(&source.bytes),
        source.scope,
        &sha256_hex(&source.bytes),
    )?;
    Ok(serde_json::to_value(
        recovery::inspect_prepared(connection, control, input, &runtime, fence, operation).await?,
    )?)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual prepared contents, scope, digest, fence and authority"]
async fn pg_organizations_prepared_comparison_exact_scope_and_fence() -> TestResult {
    let (mut source, operation) = prepared().await?;
    let f = Fixture::new().await?;
    let result = async {
        let fence = fence(&source);
        enroll(&f,&source,fence,true).await?;
        let report = check(&source,f.connect(Role::Maintenance).await?,fence,operation).await?;
        anyhow::ensure!(report["recovery"]["preparedOperationId"] == json!(operation));
        anyhow::ensure!(report["recovery"]["preparedRowsChecked"].as_u64().is_some_and(|n|n>0));
        anyhow::ensure!(report["activationAuthorized"] == false && report["recovery"]["activationAuthorized"] == false);
        anyhow::ensure!(check(&source,f.connect(Role::Maintenance).await?,fence,Uuid::new_v4()).await.is_err());
        let mut wrong = fence; wrong.revision += 1;
        anyhow::ensure!(check(&source,f.connect(Role::Maintenance).await?,wrong,operation).await.is_err());
        anyhow::ensure!(check(&source,f.connect(Role::Runtime).await?,fence,operation).await.is_err());
        let original = source.bytes.clone();
        let mut rows: Vec<Value> = std::str::from_utf8(&original)?.lines().map(serde_json::from_str).collect::<std::result::Result<_,_>>()?;
        rows.iter_mut().find(|r|r["section"]=="domain").ok_or_else(||anyhow::anyhow!("domain"))?["data"]["name"]=json!("different source");
        source.bytes = repository_tests::import::reframe(rows);
        anyhow::ensure!(check(&source,f.connect(Role::Maintenance).await?,fence,operation).await.is_err());
        source.bytes = original;
        anyhow::ensure!(sqlx::query("SELECT * FROM aegaeon.organization_import_prepared_rows_v1($1,$2,$3,$4,'domain',NULL,10)")
            .bind(operation).bind(source.scope.environment_id).bind(source.scope.domain_id).bind(sha256_hex(&source.bytes))
            .fetch_all(&source.fixture.pool).await.is_err(),"normal runtime cannot inspect maintenance contents");
        check(&source,f.connect(Role::Maintenance).await?,fence,operation).await?;
        let held: (bool,Option<Uuid>)=sqlx::query_as("SELECT enabled,import_operation_id FROM aegaeon.authorization_domains WHERE id=$1")
            .bind(source.scope.domain_id).fetch_one(&source.fixture.pool).await?;
        anyhow::ensure!(held==(false,Some(operation)));
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual prepared rows changed, missing or additional"]
async fn pg_organizations_prepared_comparison_detects_current_row_drift() -> TestResult {
    let (source, operation) = prepared().await?;
    let f = Fixture::new().await?;
    let result=async {
        let fence=fence(&source); enroll(&f,&source,fence,true).await?;
        check(&source,f.connect(Role::Maintenance).await?,fence,operation).await?;
        let mut primary=super::restoration::admin(&source).await?;
        let checked: TestResult=async {
            // An explicitly privileged fixture simulates restored/corrupted rows;
            // no production path gains this authority.
            for (change,undo) in [
                ("UPDATE aegaeon.application_organizations SET revision=revision+1 WHERE domain_id=$1", "UPDATE aegaeon.application_organizations SET revision=revision-1 WHERE domain_id=$1"),
                ("DELETE FROM aegaeon.organization_authority_outbox WHERE event_id IN (SELECT id FROM aegaeon.organization_authority_events WHERE domain_id=$1)", "INSERT INTO aegaeon.organization_authority_outbox(event_id,attempts,delivered_at) SELECT id,0,NULL FROM aegaeon.organization_authority_events WHERE domain_id=$1"),
                ("INSERT INTO aegaeon.organization_role_definitions(environment_id,domain_id,role_key,version,privileges,manages_members,assignable_roles) SELECT environment_id,domain_id,'extra-prepared-role',version,privileges,manages_members,assignable_roles FROM aegaeon.organization_role_definitions WHERE domain_id=$1 LIMIT 1", "DELETE FROM aegaeon.organization_role_definitions WHERE domain_id=$1 AND role_key='extra-prepared-role'"),
            ] {
                let mut tx=primary.begin().await?;
                sqlx::query("SET LOCAL ROLE aegaeon_subject_owner").execute(&mut *tx).await?;
                let changed=sqlx::query(change).bind(source.scope.domain_id).execute(&mut *tx).await?;
                anyhow::ensure!(changed.rows_affected()>0,"fault actually changed rows");
                tx.commit().await?;
                let refused=check(&source,f.connect(Role::Maintenance).await?,fence,operation).await;
                let mut tx=primary.begin().await?;
                sqlx::query("SET LOCAL ROLE aegaeon_subject_owner").execute(&mut *tx).await?;
                sqlx::query(undo).bind(source.scope.domain_id).execute(&mut *tx).await?;
                tx.commit().await?;
                anyhow::ensure!(refused.is_err(),"actual target drift must refuse");
                check(&source,f.connect(Role::Maintenance).await?,fence,operation).await?;
            }
            Ok(())
        }.await;
        let close=primary.close().await; checked?;close?;
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}
