use super::*;
use crate::organizations::witness::history::{restoration, Progress};
use serde_json::json;

async fn progress(control: &mut Control, fence: recovery::Fence) -> anyhow::Result<Progress> {
    Ok(control
        .history_read(fence.scope, fence.operation_id, fence.revision, 0, 1)
        .await?
        .progress)
}
async fn restore(
    control: &mut Control,
    fence: recovery::Fence,
    operation: Uuid,
    expected: &Progress,
) -> anyhow::Result<Value> {
    let (connection, runtime) = repository_tests::import::target::maintenance()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(serde_json::to_value(
        restoration::prepare(
            connection,
            control,
            restoration::Request {
                fence,
                operation_id: operation,
                runtime_role: &runtime,
                expected,
            },
        )
        .await?,
    )?)
}
async fn admin(source: &Source) -> anyhow::Result<PgConnection> {
    let options: PgConnectOptions = std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?.parse()?;
    let database = source.fixture.pool.connect_options();
    Ok(PgConnection::connect_with(
        &options.database(
            database
                .get_database()
                .ok_or_else(|| anyhow::anyhow!("primary database"))?,
        ),
    )
    .await?)
}
async fn pages(connection: &mut PgConnection, operation: Uuid) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.subject_history_restoration_pages WHERE operation_id=$1",
    )
    .bind(operation)
    .fetch_one(connection)
    .await?)
}
fn extend(source: &mut Source) -> Uuid {
    for _ in 0..257 {
        source.owners.insert(Uuid::new_v4(), Vec::new());
    }
    let owner = Uuid::new_v4();
    source.owners.insert(
        owner,
        vec![format!("Restored-{owner}"), format!("restored-{owner}")],
    );
    owner
}

#[tokio::test]
#[ignore = "requires PostgreSQL; real caller restores missing immutable facts with exact replay"]
async fn pg_organizations_history_restoration_replay_and_no_activation() -> TestResult {
    let mut source = Source::new().await?;
    let owner = extend(&mut source);
    let f = Fixture::new().await?;
    let result = async {
        let fence = fence(&source);
        enroll(&f, &source, fence, true).await?;
        let mut control = f.connect(Role::Maintenance).await?;
        let mut primary = admin(&source).await?;
        let checked: TestResult = async {
            let expected = progress(&mut control, fence).await?;
            let before = serde_json::to_value(control.current(fence.scope).await?)?;
            let users: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.end_users").fetch_one(&mut primary).await?;
            let operation = Uuid::new_v4();
            let report = restore(&mut control, fence, operation, &expected).await?;
            anyhow::ensure!(report["activationAuthorized"] == false && report["independentFactsPresent"] == true);
            anyhow::ensure!(report["pages"] == 2);
            anyhow::ensure!(restore(&mut control, fence, operation, &expected).await? == report);
            anyhow::ensure!(pages(&mut primary, operation).await? == 2);
            let subjects: Vec<String> = sqlx::query_scalar("SELECT subject FROM aegaeon.end_user_subject_reservations WHERE owner_id=$1 ORDER BY subject COLLATE \"C\"")
                .bind(owner).fetch_all(&mut primary).await?;
            anyhow::ensure!(subjects == source.owners[&owner]);
            let after: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.end_users").fetch_one(&mut primary).await?;
            anyhow::ensure!(users == after && serde_json::to_value(control.current(fence.scope).await?)? == before);
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

#[tokio::test]
#[ignore = "requires PostgreSQL; actual second page lock timeout preserves first page and exact resume"]
async fn pg_organizations_history_restoration_partial_resume() -> TestResult {
    let mut source = Source::new().await?;
    extend(&mut source);
    let f = Fixture::new().await?;
    let result = async {
        let fence = fence(&source);
        enroll(&f, &source, fence, true).await?;
        let mut control = f.connect(Role::Maintenance).await?;
        let mut primary = admin(&source).await?;
        let checked: TestResult = async {
            let expected = progress(&mut control, fence).await?;
            let operation = Uuid::new_v4();
            let mut blocker = primary.begin().await?;
            sqlx::query("LOCK TABLE aegaeon.end_user_subject_reservations IN SHARE MODE")
                .execute(&mut *blocker)
                .await?;
            let refused = restore(&mut control, fence, operation, &expected).await;
            let committed = pages(&mut blocker, operation).await?;
            blocker.rollback().await?;
            anyhow::ensure!(refused.is_err(), "blocked reservation page must fail");
            anyhow::ensure!(committed == 1, "only preceding owners page committed");
            let report = restore(&mut control, fence, operation, &expected).await?;
            anyhow::ensure!(
                report["independentFactsPresent"] == true
                    && pages(&mut primary, operation).await? == 2
            );
            Ok(())
        }
        .await;
        let close_control = control.close().await;
        let close_primary = primary.close().await;
        checked?;
        close_control?;
        close_primary?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; exact live fence, current head, issuer and maintenance role"]
async fn pg_organizations_history_restoration_scope_and_currentness() -> TestResult {
    let source = Source::new().await?;
    let f = Fixture::new().await?;
    let result = async {
        let correct = fence(&source);
        enroll(&f, &source, correct, true).await?;
        let mut control = f.connect(Role::Maintenance).await?;
        let mut primary = admin(&source).await?;
        let checked: TestResult = async {
            let expected = progress(&mut control, correct).await?;
            let operation = Uuid::new_v4();
            for changed in [
                recovery::Fence {
                    operation_id: Uuid::new_v4(),
                    ..correct
                },
                recovery::Fence {
                    revision: 2,
                    ..correct
                },
                recovery::Fence {
                    scope: Scope {
                        environment_id: Uuid::new_v4(),
                        ..correct.scope
                    },
                    ..correct
                },
                recovery::Fence {
                    scope: Scope {
                        deployment_id: Uuid::new_v4(),
                        ..correct.scope
                    },
                    ..correct
                },
            ] {
                anyhow::ensure!(restore(&mut control, changed, operation, &expected)
                    .await
                    .is_err());
            }
            for case in 0..3 {
                let mut changed = expected.clone();
                match case {
                    0 => changed.digest = "0".repeat(64),
                    1 => changed.issuer_host.push_str(".foreign"),
                    _ => changed.sealed = false,
                }
                anyhow::ensure!(restore(&mut control, correct, operation, &changed)
                    .await
                    .is_err());
            }
            let mut runtime = f.connect(Role::Runtime).await?;
            let refused = restore(&mut runtime, correct, operation, &expected)
                .await
                .is_err();
            runtime.close().await?;
            anyhow::ensure!(refused && pages(&mut primary, operation).await? == 0);
            restore(&mut control, correct, operation, &expected).await?;
            Ok(())
        }
        .await;
        let close_control = control.close().await;
        let close_primary = primary.close().await;
        checked?;
        close_control?;
        close_primary?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; conflicting live independent subject ownership cannot be acknowledged"]
async fn pg_organizations_history_restoration_owner_conflict() -> TestResult {
    let mut source = Source::new().await?;
    let subjects = source
        .owners
        .values_mut()
        .find(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("subject fixture"))?;
    let subject = subjects.remove(0);
    let owner = Uuid::new_v4();
    source.owners.insert(owner, vec![subject]);
    let f = Fixture::new().await?;
    let result = async {
        let fence = fence(&source);
        enroll(&f, &source, fence, true).await?;
        let mut control = f.connect(Role::Maintenance).await?;
        let mut primary = admin(&source).await?;
        let checked: TestResult = async {
            let expected = progress(&mut control, fence).await?;
            let operation = Uuid::new_v4();
            anyhow::ensure!(restore(&mut control, fence, operation, &expected)
                .await
                .is_err());
            anyhow::ensure!(pages(&mut primary, operation).await? == 0);
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM aegaeon.end_user_identity_owners WHERE owner_id=$1)",
            )
            .bind(owner)
            .fetch_one(&mut primary)
            .await?;
            anyhow::ensure!(!exists, "all facts in conflicting page roll back");
            Ok(())
        }
        .await;
        let close_control = control.close().await;
        let close_primary = primary.close().await;
        checked?;
        close_control?;
        close_primary?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; terminated live journal cannot become an empty successful restoration"]
async fn pg_organizations_history_restoration_store_disconnect() -> TestResult {
    let source = Source::new().await?;
    let mut f = Fixture::new().await?;
    let result = async {
        let fence = fence(&source);
        enroll(&f, &source, fence, true).await?;
        let mut control = f.connect(Role::Maintenance).await?;
        let expected = progress(&mut control, fence).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(
                control
                    .connection
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("control"))?,
            )
            .await?;
        let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .fetch_one(&mut f.owner)
            .await?;
        anyhow::ensure!(terminated);
        let operation = Uuid::new_v4();
        let refused = restore(&mut control, fence, operation, &expected)
            .await
            .is_err();
        // Broken transport close may fail; the backend was independently terminated.
        let _ = control.close().await;
        anyhow::ensure!(refused);
        let mut healthy = f.connect(Role::Maintenance).await?;
        let recovered = restore(&mut healthy, fence, operation, &expected).await;
        let close = healthy.close().await;
        recovered?;
        close?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; compiled catalog rejects newly broadened runtime receipt privileges"]
async fn pg_organizations_history_restoration_catalog_authority() -> TestResult {
    let source = Source::new().await?;
    let f = Fixture::new().await?;
    let result = async {
        let fence = fence(&source);
        enroll(&f, &source, fence, true).await?;
        let mut control = f.connect(Role::Maintenance).await?;
        let mut primary = admin(&source).await?;
        let checked: TestResult = async {
            let expected = progress(&mut control, fence).await?;
            let operation = Uuid::new_v4();
            let (connection, runtime) = repository_tests::import::target::maintenance()
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            connection.close().await?;
            let role = format!("\"{}\"", runtime.replace('"', "\"\""));
            for table in [
                "subject_history_restorations",
                "subject_history_restoration_pages",
            ] {
                sqlx::raw_sql(&format!("GRANT SELECT ON aegaeon.{table} TO {role}"))
                    .execute(&mut primary)
                    .await?;
                let refused = restore(&mut control, fence, operation, &expected)
                    .await
                    .is_err();
                sqlx::raw_sql(&format!("REVOKE SELECT ON aegaeon.{table} FROM {role}"))
                    .execute(&mut primary)
                    .await?;
                anyhow::ensure!(
                    refused && pages(&mut primary, operation).await? == 0,
                    "catalog must reject runtime grant to {table}"
                );
            }
            anyhow::ensure!(
                restore(&mut control, fence, operation, &expected).await?["activationAuthorized"]
                    == json!(false)
            );
            Ok(())
        }
        .await;
        let close_control = control.close().await;
        let close_primary = primary.close().await;
        checked?;
        close_control?;
        close_primary?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}
