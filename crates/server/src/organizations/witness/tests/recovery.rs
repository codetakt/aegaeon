use super::*;
use crate::organizations::{
    repository_tests,
    snapshot::{input::Input, staging::recovery},
};
use crate::subject_ownership::history::sha256_hex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Cursor;

mod restoration;

struct Source {
    fixture: repository_tests::Fixture,
    bytes: Vec<u8>,
    scope: crate::organizations::Scope,
    issuer: String,
    owners: BTreeMap<Uuid, Vec<String>>,
}
impl Source {
    async fn new() -> anyhow::Result<Self> {
        let fixture = repository_tests::Fixture::new()
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let (bytes, scope) = repository_tests::import::target::prospective(&fixture)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let mut owners = BTreeMap::new();
        let mut issuer = None;
        for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let row: Value = serde_json::from_slice(line)?;
            match row["section"].as_str() {
                Some("namespace") => {
                    issuer = row["data"]["issuer_host"].as_str().map(str::to_owned)
                }
                Some("owners") => {
                    let owner: Uuid = serde_json::from_value(row["data"]["owner_id"].clone())?;
                    owners.insert(owner, Vec::new());
                }
                Some("subject_history") => {
                    let owner: Uuid = serde_json::from_value(row["data"]["owner_id"].clone())?;
                    let subject = row["data"]["subject"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("subject"))?;
                    owners
                        .get_mut(&owner)
                        .ok_or_else(|| anyhow::anyhow!("owner"))?
                        .push(subject.to_owned());
                }
                _ => (),
            }
        }
        let issuer = issuer.ok_or_else(|| anyhow::anyhow!("issuer"))?;
        anyhow::ensure!(!owners.is_empty());
        Ok(Self {
            fixture,
            bytes,
            scope,
            issuer,
            owners,
        })
    }
    fn plan(&self, scope: Scope) -> anyhow::Result<crate::organizations::witness::history::Plan> {
        let owners: Vec<_> = self
            .owners
            .iter()
            .map(|(id, subjects)| (*id, subjects.iter().map(String::as_str).collect()))
            .collect();
        super::history::plan_for_issuer(scope, &owners, &self.issuer)
    }
    async fn check(&self, control: Control, fence: recovery::Fence) -> anyhow::Result<Value> {
        let (connection, runtime) = repository_tests::import::target::maintenance()
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let input = Input::new(
            Cursor::new(&self.bytes),
            self.scope,
            &sha256_hex(&self.bytes),
        )?;
        Ok(serde_json::to_value(
            recovery::inspect(connection, control, input, &runtime, fence).await?,
        )?)
    }
    async fn finish(self, result: TestResult) -> TestResult {
        let cleanup = self
            .fixture
            .cleanup(Ok(()))
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()));
        result.and(cleanup)
    }
}
fn fence(source: &Source) -> recovery::Fence {
    recovery::Fence {
        scope: Scope {
            environment_id: source.scope.environment_id,
            deployment_id: Uuid::new_v4(),
        },
        operation_id: Uuid::new_v4(),
        revision: 1,
    }
}
async fn enroll(f: &Fixture, source: &Source, fence: recovery::Fence, seal: bool) -> TestResult {
    let plan = source.plan(fence.scope)?;
    let mut control = f.connect(Role::Maintenance).await?;
    control.initialize(fence.scope, fence.operation_id).await?;
    control
        .history_begin(fence.scope, fence.operation_id, 1, &plan)
        .await?;
    let mut offset = 0;
    for entries in plan.batches() {
        offset = control
            .history_batch(fence.scope, fence.operation_id, 1, offset, entries)
            .await?
            .sequence;
    }
    if seal {
        control
            .history_seal(fence.scope, fence.operation_id, 1)
            .await?;
    }
    control.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual primary and independent multi-page recovery history"]
async fn pg_organizations_recovery_history_exact_and_unrelated_owners() -> TestResult {
    let mut source = Source::new().await?;
    let f = Fixture::new().await?;
    let result = async {
        for _ in 0..257 {
            source.owners.insert(
                Uuid::new_v4(),
                vec![format!("unrelated-{}", Uuid::new_v4())],
            );
        }
        let fence = fence(&source);
        enroll(&f, &source, fence, true).await?;
        let mut control = f.connect(Role::Maintenance).await?;
        let before = serde_json::to_value(control.current(fence.scope).await?)?;
        control.close().await?;
        let report = source
            .check(f.connect(Role::Maintenance).await?, fence)
            .await?;
        anyhow::ensure!(report["recovery"]["relevantOwnerHistoryChecked"] == true);
        anyhow::ensure!(
            report["activationAuthorized"] == false && report["targetDependenciesChecked"] == false
        );
        anyhow::ensure!(report["recovery"]["activationAuthorized"] == false);
        let mut control = f.connect(Role::Maintenance).await?;
        anyhow::ensure!(serde_json::to_value(control.current(fence.scope).await?)? == before);
        control.close().await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM aegaeon.authorization_domains WHERE id=$1)",
        )
        .bind(source.scope.domain_id)
        .fetch_one(&source.fixture.pool)
        .await?;
        anyhow::ensure!(!exists, "inspection never prepares destination");
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; current retained reservation after source capture must refuse"]
async fn pg_organizations_recovery_history_missing_current_reservation() -> TestResult {
    let source = Source::new().await?;
    let f = Fixture::new().await?;
    let result = async {
        let mut fence = fence(&source);
        enroll(&f, &source, fence, true).await?;
        source
            .check(f.connect(Role::Maintenance).await?, fence)
            .await?;
        let mut maintenance = f.connect(Role::Maintenance).await?;
        let plan = source.plan(fence.scope)?;
        let selected =
            super::history::activated(&mut maintenance, fence.scope, fence.operation_id, &plan)
                .await?;
        let mut runtime = f.connect(Role::Runtime).await?;
        let admission = runtime
            .acquire(fence.scope, &selected, Uuid::new_v4())
            .await?;
        let owner = *source
            .owners
            .keys()
            .next()
            .ok_or_else(|| anyhow::anyhow!("owner"))?;
        runtime
            .history_reserve(&admission, owner, "CaseSensitive-restored-history")
            .await?;
        runtime
            .history_reserve(&admission, owner, "casesensitive-restored-history")
            .await?;
        runtime.complete(&admission).await?;
        runtime.close().await?;
        let state = maintenance.fence(fence.scope, Uuid::new_v4(), 3).await?;
        fence.operation_id = state.operation_id;
        fence.revision = state.revision;
        maintenance.close().await?;
        let result = source
            .check(f.connect(Role::Maintenance).await?, fence)
            .await;
        anyhow::ensure!(
            result.is_err(),
            "snapshot without current retained reservations must refuse"
        );
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; exact recovery scope, fence and restricted control role"]
async fn pg_organizations_recovery_history_scope_and_fence() -> TestResult {
    let source = Source::new().await?;
    let f = Fixture::new().await?;
    let result = async {
        let correct = fence(&source);
        enroll(&f, &source, correct, true).await?;
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
            anyhow::ensure!(source
                .check(f.connect(Role::Maintenance).await?, changed)
                .await
                .is_err());
        }
        anyhow::ensure!(source
            .check(f.connect(Role::Runtime).await?, correct)
            .await
            .is_err());
        source
            .check(f.connect(Role::Maintenance).await?, correct)
            .await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; incomplete, active and pending history never supplies recovery"]
async fn pg_organizations_recovery_history_incomplete_active_and_pending() -> TestResult {
    let source = Source::new().await?;
    let f = Fixture::new().await?;
    let result = async {
        let mut fence = fence(&source);
        enroll(&f, &source, fence, false).await?;
        anyhow::ensure!(source
            .check(f.connect(Role::Maintenance).await?, fence)
            .await
            .is_err());
        let mut maintenance = f.connect(Role::Maintenance).await?;
        maintenance
            .history_seal(fence.scope, fence.operation_id, 1)
            .await?;
        let selected = super::history::activated(
            &mut maintenance,
            fence.scope,
            fence.operation_id,
            &source.plan(fence.scope)?,
        )
        .await?;
        fence.revision = 3;
        anyhow::ensure!(source
            .check(f.connect(Role::Maintenance).await?, fence)
            .await
            .is_err());
        let mut runtime = f.connect(Role::Runtime).await?;
        let admission = runtime
            .acquire(fence.scope, &selected, Uuid::new_v4())
            .await?;
        let state = maintenance.fence(fence.scope, Uuid::new_v4(), 3).await?;
        fence.operation_id = state.operation_id;
        fence.revision = state.revision;
        anyhow::ensure!(source
            .check(f.connect(Role::Maintenance).await?, fence)
            .await
            .is_err());
        anyhow::ensure!(maintenance.current(fence.scope).await?.pending == 1);
        runtime.complete(&admission).await?;
        runtime.close().await?;
        maintenance.close().await?;
        source
            .check(f.connect(Role::Maintenance).await?, fence)
            .await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; absent owners, conflicting subject ownership and exact issuer"]
async fn pg_organizations_recovery_history_conflicting_retained_facts() -> TestResult {
    let mut source = Source::new().await?;
    let original = source.owners.clone();
    let issuer = source.issuer.clone();
    let result = async {
        for case in 0..3 {
            source.owners = original.clone();
            source.issuer = issuer.clone();
            match case {
                0 => {
                    source.owners.clear();
                }
                1 => {
                    let subjects = source
                        .owners
                        .values_mut()
                        .find(|subjects| !subjects.is_empty())
                        .ok_or_else(|| anyhow::anyhow!("subject fixture"))?;
                    let subject = subjects.remove(0);
                    source.owners.insert(Uuid::new_v4(), vec![subject]);
                }
                _ => {
                    source.issuer.push_str(".foreign");
                }
            }
            let f = Fixture::new().await?;
            let checked: TestResult = async {
                let fence = fence(&source);
                enroll(&f, &source, fence, true).await?;
                anyhow::ensure!(
                    source
                        .check(f.connect(Role::Maintenance).await?, fence)
                        .await
                        .is_err(),
                    "conflict case {case}"
                );
                Ok(())
            }
            .await;
            let cleanup = f.finish().await;
            checked.and(cleanup)?;
        }
        Ok(())
    }
    .await;
    source.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual independent store disconnect refuses without mutation"]
async fn pg_organizations_recovery_history_store_disconnect() -> TestResult {
    let source = Source::new().await?;
    let mut f = Fixture::new().await?;
    let result = async {
        let fence = fence(&source);
        enroll(&f, &source, fence, true).await?;
        let mut broken = f.connect(Role::Maintenance).await?;
        let before = serde_json::to_value(broken.current(fence.scope).await?)?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(
                broken
                    .connection
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("control connection"))?,
            )
            .await?;
        let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .fetch_one(&mut f.owner)
            .await?;
        anyhow::ensure!(terminated);
        anyhow::ensure!(
            source.check(broken, fence).await.is_err(),
            "store loss cannot substitute an empty journal"
        );
        let mut healthy = f.connect(Role::Maintenance).await?;
        anyhow::ensure!(serde_json::to_value(healthy.current(fence.scope).await?)? == before);
        healthy.close().await?;
        source
            .check(f.connect(Role::Maintenance).await?, fence)
            .await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    source.finish(result.and(cleanup)).await
}
