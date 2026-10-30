use super::*;
use crate::organizations::snapshot::{input::Input, staging, Reader};
use crate::subject_ownership::history::{sha256_hex, HashChain};
use serde_json::{json, Value};
use sqlx::{Connection, PgConnection};
use std::io::Cursor;
#[tokio::test]
#[ignore = "requires restricted PostgreSQL; writer/export/import integer domains agree"]
async fn pg_organizations_import_source_retains_full_audit_integer_domain() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let data = json!({"signed":i64::MIN,"unsigned":u64::MAX});
        let mut writer = f.pool.begin().await?;
        repository::event(&mut writer, &f.organization, &f.actor, "integer-domain-fixture", data.clone()).await?;
        writer.commit().await?;
        let stored: Value = sqlx::query_scalar("SELECT data FROM aegaeon.organization_authority_events WHERE domain_id=$1 AND event_type='integer-domain-fixture'")
            .bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;
        assert_eq!(stored, data);
        let bytes = export(&f).await?;
        let mut input = Input::new(Cursor::new(&bytes), f.organization.scope, &sha256_hex(&bytes))?;
        let mut found = false;
        while let Some(row) = input.next_row()? {
            if row.section == "audit" && row.data["event_type"] == "integer-domain-fixture" {
                assert_eq!(row.data["data"], data);
                assert!(row.exact_data.contains("18446744073709551615"));
                assert!(row.exact_data.contains("-9223372036854775808"));
                found = true;
            }
        }
        assert!(found);
        input.finish()?;
        assert!(inspect(&f, &bytes).await.is_ok());
        Ok(())
    }.await;
    f.cleanup(result).await
}
mod faults;
mod receipts;
mod semantics;

pub(super) async fn export(f: &Fixture) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut tx = f.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let mut reader = Reader::start(&mut tx, f.organization.scope).await?;
    let mut bytes = reader.header_line()?;
    while let Some(page) = reader.next(&mut tx).await? {
        for line in page {
            bytes.extend(line);
        }
    }
    tx.commit().await?;
    bytes.extend(reader.manifest_line()?);
    Ok(bytes)
}

async fn connection(f: &Fixture) -> Result<PgConnection, sqlx::Error> {
    let options = (*f.pool.connect_options()).clone().options([
        ("statement_timeout", "5000"),
        ("lock_timeout", "1000"),
        ("idle_in_transaction_session_timeout", "30000"),
        ("transaction_timeout", "3600000"),
    ]);
    PgConnection::connect_with(&options).await
}

pub(super) async fn inspect(
    f: &Fixture,
    bytes: &[u8],
) -> Result<staging::SourceInspection, Box<dyn std::error::Error>> {
    let input = Input::new(Cursor::new(bytes), f.organization.scope, &sha256_hex(bytes))?;
    Ok(staging::inspect_source(connection(f).await?, input).await?)
}

pub(super) fn records(bytes: &[u8]) -> Vec<Value> {
    std::str::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}

/// Deliberately re-sign the format checksums after semantic corruption: a
/// checksum is not semantic consistency or authority to adopt a source.
pub(super) fn reframe(mut records: Vec<Value>) -> Vec<u8> {
    let mut manifest = records.pop().unwrap();
    let mut bytes = Vec::new();
    for section in manifest["sections"].as_array_mut().unwrap() {
        let name = section["section"].as_str().unwrap();
        let mut chain = HashChain::new(&format!("aegaeon-organizations-snapshot-v1:{name}"));
        for row in records
            .iter()
            .filter(|r| r["record"] == "row" && r["section"] == name)
        {
            chain
                .push(
                    row["key"].as_str().unwrap(),
                    &serde_json::to_vec(&row["data"]).unwrap(),
                )
                .unwrap();
        }
        let (count, digest) = chain.finish();
        section["count"] = json!(count);
        section["sha256"] = json!(digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>());
    }
    // Native row envelope must embed the same serialized data used above.
    for value in records {
        bytes.extend(serde_json::to_vec(&value).unwrap());
        bytes.push(b'\n');
    }
    manifest["contentBytes"] = json!(bytes.len());
    bytes.extend(serde_json::to_vec(&manifest).unwrap());
    bytes.push(b'\n');
    bytes
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; native export and inactive private staging"]
async fn pg_organizations_import_source_inspection_keeps_runtime_rows_and_closes_session(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let bytes = export(&f).await?;
        let before: Value = sqlx::query_scalar(
            "SELECT to_jsonb(o) FROM aegaeon.application_organizations o WHERE id=$1",
        )
        .bind(f.organization.id)
        .fetch_one(&f.pool)
        .await?;
        let mut supplier = connection(&f).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut supplier)
            .await?;
        let input = Input::new(
            Cursor::new(&bytes),
            f.organization.scope,
            &sha256_hex(&bytes),
        )?;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
                observe_session_exit(&f.pool, pid),
            )
            .await
            .is_err(),
            "the observer must not accept a still-owned session"
        );
        let inspected = staging::inspect_source(supplier, input).await?;
        assert_eq!(inspected.integrity.sha256, sha256_hex(&bytes));
        let outcome = serde_json::to_value(inspected)?;
        assert_eq!(outcome["sourceGraphChecked"], true);
        assert_eq!(outcome["targetDependenciesChecked"], false);
        assert_eq!(outcome["activationAuthorized"], false);
        let after: Value = sqlx::query_scalar(
            "SELECT to_jsonb(o) FROM aegaeon.application_organizations o WHERE id=$1",
        )
        .bind(f.organization.id)
        .fetch_one(&f.pool)
        .await?;
        assert_eq!(before, after);
        // close() sends Terminate and shuts down the owned transport after
        // rollback acknowledgment. PostgreSQL removes its backend asynchronously.
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            observe_session_exit(&f.pool, pid),
        )
        .await??;
        assert!(
            inspect(&f, &bytes).await.is_ok(),
            "a fresh inspection is independent"
        );
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; complete hashes do not adopt incomplete ownership"]
async fn pg_organizations_import_source_rejects_missing_history_and_conflicting_row_identity(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let bytes = export(&f).await?;
        for section in [
            "owners",
            "subject_history",
            "domain",
            "namespace",
            "environment_dependency",
        ] {
            let mut changed = records(&bytes);
            changed.retain(|r| r["section"] != section);
            let rejected = inspect(&f, &reframe(changed)).await;
            assert!(
                rejected.is_err(),
                "{section} cannot be inferred from checksums"
            );
        }
        let mut changed = records(&bytes);
        let org = changed
            .iter_mut()
            .find(|r| r["section"] == "organizations")
            .ok_or("organization")?;
        org["data"]["id"] = json!(Uuid::new_v4());
        assert!(inspect(&f, &reframe(changed)).await.is_err());
        let mut changed = records(&bytes);
        let member = changed
            .iter_mut()
            .find(|r| r["section"] == "memberships")
            .ok_or("membership")?;
        member["data"]["organization_id"] = json!(Uuid::new_v4());
        assert!(inspect(&f, &reframe(changed)).await.is_err());
        let mut changed = records(&bytes);
        changed.retain(|r| r["section"] != "memberships");
        let outside = inspect(&f, &reframe(changed))
            .await
            .expect_err("unreferenced owners are not this domain's inventory");
        assert!(outside.to_string().contains("owner is outside"));
        assert!(inspect(&f, &bytes).await.is_ok());
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; credential injection, malformed scalars and store boundary"]
async fn pg_organizations_import_source_refuses_columns_types_unbounded_supplier_and_replay(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let bytes = export(&f).await?;
        for (key, value) in [
            ("password_hash", json!("injected")),
            ("revision", json!("1")),
            ("grant_generation", json!(0)),
        ] {
            let mut changed = records(&bytes);
            let org = changed
                .iter_mut()
                .find(|r| r["section"] == "organizations")
                .ok_or("organization")?;
            org["data"][key] = value;
            assert!(inspect(&f, &reframe(changed)).await.is_err(), "{key}");
        }
        let mut unbounded = connection(&f).await?;
        sqlx::query("SET statement_timeout=0")
            .execute(&mut unbounded)
            .await?;
        let input = Input::new(
            Cursor::new(&bytes),
            f.organization.scope,
            &sha256_hex(&bytes),
        )?;
        assert!(staging::inspect_source(unbounded, input).await.is_err());
        let mut occupied = connection(&f).await?;
        sqlx::query("CREATE TEMP TABLE organization_import_rows(injected text)")
            .execute(&mut occupied)
            .await?;
        let input = Input::new(
            Cursor::new(&bytes),
            f.organization.scope,
            &sha256_hex(&bytes),
        )?;
        assert!(
            staging::inspect_source(occupied, input).await.is_err(),
            "never reuse preexisting staging"
        );
        assert!(inspect(&f, &bytes).await.is_ok());
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

/// Exercise the same exporter and source inspector after real routed operations.
pub(crate) async fn validate_fixture_source(f: &Fixture) -> TestResult {
    let bytes = export(f).await?;
    inspect(f, &bytes).await?;
    Ok(())
}

// Observe the identified backend, never a global connection count. Each caller
// supplies its own finite deadline, including the live-session negative control.
async fn observe_session_exit(pool: &sqlx::PgPool, pid: i32) -> Result<(), sqlx::Error> {
    loop {
        let present: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1)")
                .bind(pid)
                .fetch_one(pool)
                .await?;
        if !present {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
