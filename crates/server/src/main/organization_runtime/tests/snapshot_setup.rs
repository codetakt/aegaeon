//! Native export fixture before the packaged maintenance process takes ownership.
use super::*;
use crate::organizations::{
    operators::mutations,
    repository::{ActorKind, AuditActor},
    snapshot::Reader,
};
use std::{io::Write, os::unix::fs::OpenOptionsExt};

pub(super) async fn retain(context: &super::fixture::Context) -> Result<()> {
    // The external fixture clones reconciled dependencies before any domain
    // exists. Its private marker is a test barrier, never a production fence.
    let input = PathBuf::from(std::env::var("AEGAEON_TEST_ORGANIZATION_STARTUP_FIXTURE")?);
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(input.with_file_name("snapshot-dependencies-ready"))?
        .sync_all()?;
    tokio::time::timeout(Duration::from_secs(30), async {
        while !input
            .with_file_name("snapshot-dependencies-captured")
            .exists()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let initialized = &context.initialized;
    let pool = &context.prepared.startup.pool;
    let mut tx = pool.begin().await?;
    let actor = AuditActor {
        id: initialized.administrator_id,
        kind: ActorKind::Operator,
        basis: None,
        client_id: "operator-console".into(),
        client_registration_id: None,
        request_id: "snapshot-fixture".into(),
        reason: "explicit fixture provisioning".into(),
    };
    let created = mutations::bootstrap_default(
        &mut tx,
        initialized.team_id,
        initialized.environment_id,
        &actor,
        "snapshot-bootstrap",
    )
    .await?;
    sqlx::query("UPDATE aegaeon.authorization_domains SET enabled=true,revision=2 WHERE id=$1")
        .bind(created.scope.domain_id)
        .execute(&mut *tx)
        .await?;
    for external in ["tenant/A", "Tenant/A", "組織/é", "組織/e\u{301}"] {
        sqlx::query("INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state) VALUES($1,$2,$3,$4,'active')")
            .bind(Uuid::new_v4()).bind(initialized.environment_id)
            .bind(created.scope.domain_id).bind(external).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let scope = created.scope;
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let mut reader = Reader::start(&mut tx, scope).await?;
    let mut bytes = reader.header_line()?;
    while let Some(page) = reader.next(&mut tx).await? {
        for line in page {
            bytes.extend(line);
        }
    }
    tx.commit().await?;
    bytes.extend(reader.manifest_line()?);
    for (name, bytes) in [
        ("source-snapshot.jsonl", bytes),
        ("snapshot-scope.json", serde_json::to_vec(&scope)?),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(input.with_file_name(name))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    Ok(())
}
