use super::*;

pub(in crate::organizations::repository_tests) async fn prepare(
    bytes: &[u8],
    scope: Scope,
    operation: Uuid,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (connection, runtime) = target::maintenance().await?;
    let input = Input::new(Cursor::new(bytes), scope, &sha256_hex(bytes))?;
    Ok(staging::prepare::inactive(connection, input, &runtime, operation).await?)
}

// A separate prospective scope requires fresh global IDs for all owned rows.
// The production importer copies these explicit source IDs without rewriting.
pub(in crate::organizations::repository_tests) async fn prospective(
    f: &Fixture,
) -> Result<(Vec<u8>, Scope), Box<dyn std::error::Error>> {
    let (bytes, scope) = target::prospective(f).await?;
    let mut rows = records(&bytes);
    let replacements: Vec<(String, String)> = rows
        .iter()
        .filter(|r| {
            matches!(
                r["section"].as_str(),
                Some(
                    "organizations"
                        | "client_bindings"
                        | "operators"
                        | "invitations"
                        | "challenges"
                        | "identity_requests"
                        | "administrative_grants"
                        | "audit"
                )
            )
        })
        .filter_map(|r| {
            r["data"]["id"]
                .as_str()
                .map(|id| (id.to_owned(), Uuid::new_v4().to_string()))
        })
        .collect();
    for row in &mut rows {
        let mut text = serde_json::to_string(row)?;
        for (before, after) in &replacements {
            text = text.replace(before, after);
        }
        *row = serde_json::from_str(&text)?;
    }
    order_rows(&mut rows);
    Ok((reframe(rows), scope))
}

fn order_rows(rows: &mut [Value]) {
    let mut start = 1;
    while start < rows.len() - 1 {
        let mut end = start + 1;
        while end < rows.len() - 1 && rows[end]["section"] == rows[start]["section"] {
            end += 1;
        }
        rows[start..end].sort_by_key(|r| r["key"].as_str().unwrap().to_owned());
        start = end;
    }
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; inactive copy, held authority and exact replay"]
async fn pg_organizations_import_inactive_preserves_rows_and_rejects_normal_activation(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        super::super::operators::principal(&f).await?;
        super::super::operators::grant(&f,json!(["configure","export"])).await?;
        let mut current = f.pool.begin().await?;
        super::super::super::operators::lock_operator_authority(&mut current, f.organization.scope,
            f.env.team_id, f.actor.id, super::super::super::operators::Capability::Configure).await?;
        current.rollback().await?;
        let (bytes, scope) = prospective(&f).await?;
        let operation = Uuid::new_v4();
        let receipt = prepare(&bytes, scope, operation).await?;
        assert_eq!(receipt["state"], "prepared");
        assert_eq!(receipt["activationAuthorized"], false);
        assert_eq!(receipt["cutoverDependenciesChecked"], false);
        let held: (bool, Option<Uuid>) = sqlx::query_as("SELECT enabled,import_operation_id FROM aegaeon.authorization_domains WHERE id=$1")
            .bind(scope.domain_id).fetch_one(&f.pool).await?;
        assert_eq!(held, (false, Some(operation)));
        let mut tx = f.pool.begin().await?;
        assert!(repository::lock_domain(&mut tx, scope).await.is_err());
        tx.rollback().await?;
        let mut tx = f.pool.begin().await?;
        assert!(super::super::super::operators::lock_operator_authority(&mut tx, scope, f.env.team_id, f.actor.id,
            super::super::super::operators::Capability::Configure).await.is_err(), "ordinary configuration cannot adopt an import");
        tx.rollback().await?;
        for sql in [
            "UPDATE aegaeon.authorization_domains SET enabled=true WHERE id=$1",
            "UPDATE aegaeon.authorization_domains SET revision=revision+1 WHERE id=$1",
            "UPDATE aegaeon.authorization_domains SET import_operation_id=NULL WHERE id=$1",
            "UPDATE aegaeon.application_organizations SET revision=revision+1 WHERE domain_id=$1",
            "UPDATE aegaeon.organization_memberships SET state='removed' WHERE domain_id=$1",
        ] {
            assert!(sqlx::query(sql).bind(scope.domain_id).execute(&f.pool).await.is_err(), "inactive guard: {sql}");
        }
        let rows = records(&bytes);
        for row in rows.iter().filter(|r| r["section"] == "organizations") {
            let actual: Value = sqlx::query_scalar("SELECT to_jsonb(r) FROM (SELECT id,environment_id,domain_id,external_id,state,revision,grant_generation,created_at FROM aegaeon.application_organizations WHERE id=$1) r")
                .bind(row["data"]["id"].as_str().ok_or("organization id")?.parse::<Uuid>()?).fetch_one(&f.pool).await?;
            assert_eq!(actual,row["data"]);
        }
        assert_eq!(prepare(&bytes, scope, operation).await?,receipt, "lost reply reconciles exact operation");
        assert!(prepare(&bytes, scope, Uuid::new_v4()).await.is_err(), "new operation cannot overwrite existing scope");
        let mut changed = records(&bytes);
        changed.iter_mut().find(|r| r["section"]=="domain").ok_or("domain")?["data"]["name"]=json!("conflicting replay");
        assert!(prepare(&reframe(changed), scope, operation).await.is_err());
        let (mut maintenance, _) = target::maintenance().await?;
        assert!(sqlx::query("UPDATE aegaeon.authorization_domains SET enabled=true WHERE id=$1").bind(scope.domain_id).execute(&mut maintenance).await.is_err());
        assert!(sqlx::query("SELECT * FROM aegaeon.organization_import_operations").execute(&mut maintenance).await.is_err());
        maintenance.close().await?;
        assert!(f.access().await.is_ok(), "ordinary source remains usable");
        if std::env::var("AEGAEON_TEST_IMPORT_PREPARE_FIXTURE").as_deref()==Ok("1") {
            use base64::Engine as _;
            let (bytes,_) = prospective(&f).await?;
            println!("INACTIVE_IMPORT_CLI_FIXTURE {}",base64::engine::general_purpose::STANDARD.encode(bytes));
        }
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; concurrent exact operation has one durable destination"]
async fn pg_organizations_import_inactive_concurrent_replay_has_one_destination() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let (bytes,scope) = prospective(&f).await?;
        let operation = Uuid::new_v4();
        let (first,second) = tokio::join!(prepare(&bytes,scope,operation),prepare(&bytes,scope,operation));
        assert!(first.is_ok() || second.is_ok(),"one bounded writer must succeed");
        let retained = prepare(&bytes,scope,operation).await?;
        for receipt in [first,second].into_iter().flatten() { assert_eq!(receipt,retained); }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.authorization_domains WHERE id=$1 AND import_operation_id=$2 AND NOT enabled")
            .bind(scope.domain_id).bind(operation).fetch_one(&f.pool).await?;
        assert_eq!(count,1);
        assert!(prepare(&bytes,scope,Uuid::new_v4()).await.is_err());
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; actual late conflict rolls back all preparation writes"]
async fn pg_organizations_import_inactive_conflict_rolls_back_and_recovers() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let original = records(&export(&f).await?);
        let original_id = original
            .iter()
            .find(|r| r["section"] == "audit")
            .and_then(|r| r["data"]["id"].as_str())
            .ok_or("original audit")?;
        let (bytes, scope) = prospective(&f).await?;
        let mut changed = records(&bytes);
        let prospective_id = changed
            .iter()
            .find(|r| r["section"] == "audit")
            .and_then(|r| r["data"]["id"].as_str())
            .ok_or("prospective audit")?
            .to_owned();
        for row in &mut changed {
            *row = serde_json::from_str(
                &serde_json::to_string(row)?.replace(&prospective_id, original_id),
            )?;
        }
        order_rows(&mut changed);
        let conflicting = reframe(changed);
        let operation = Uuid::new_v4();
        let error = prepare(&conflicting, scope, operation)
            .await
            .expect_err("late audit collision");
        assert!(
            error.to_string().contains("store failed"),
            "must reach the actual destination writer: {error}"
        );
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM aegaeon.authorization_domains WHERE id=$1)",
        )
        .bind(scope.domain_id)
        .fetch_one(&f.pool)
        .await?;
        assert!(
            !exists,
            "earlier domain and organization writes must roll back"
        );
        let (mut maintenance, _) = target::maintenance().await?;
        let receipt: Option<Value> =
            sqlx::query_scalar("SELECT aegaeon.organization_import_operation_v1($1,$2,$3,$4)")
                .bind(operation)
                .bind(scope.environment_id)
                .bind(scope.domain_id)
                .bind(sha256_hex(&conflicting))
                .fetch_one(&mut maintenance)
                .await?;
        assert!(
            receipt.is_none(),
            "failed transaction has no committed operation"
        );
        maintenance.close().await?;
        assert_eq!(
            prepare(&bytes, scope, operation).await?["state"],
            "prepared"
        );
        Ok(())
    }
    .await;
    f.cleanup(result).await
}
