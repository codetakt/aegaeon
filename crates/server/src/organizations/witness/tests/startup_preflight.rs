//! Actual SQL diagnostics, independent of primary/Redis observation drivers.
use super::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const SEED: &str = include_str!("../../../../../../tests/organizations/startup_preflight.sql");
const QUERY: &str = "SELECT organization_witness.startup_preflight($1,$2,$3,$4)";

pub(super) fn scope() -> Scope {
    Scope {
        deployment_id: Uuid::from_u128(0x10000000000000000000000000000001),
        environment_id: Uuid::from_u128(0x10000000000000000000000000000002),
    }
}

pub(super) fn selected(parent: bool) -> Value {
    json!({
        "epoch": if parent {
            "10000000-0000-0000-0000-000000000003"
        } else {
            "10000000-0000-0000-0000-000000000004"
        },
        "primary": "10000000-0000-0000-0000-000000000005",
        "token_store": "10000000-0000-0000-0000-000000000006",
        "source_sha256": "a".repeat(64),
        "history_sha256": "b".repeat(64),
        "acceptance_sha256": "c".repeat(64),
    })
}

async fn preflight(
    connection: &mut PgConnection,
    scope: Scope,
    parent: &Value,
    child: &Value,
) -> std::result::Result<Value, sqlx::Error> {
    sqlx::query_scalar(QUERY)
        .bind(scope.deployment_id)
        .bind(scope.environment_id)
        .bind(parent)
        .bind(child)
        .fetch_one(connection)
        .await
}

// Compare every durable table, including generations, pending owners, retained
// observations and checkpoints. Counts alone cannot establish no mutation.
pub(super) async fn snapshot(f: &mut Fixture) -> anyhow::Result<BTreeMap<String, Value>> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_tables WHERE schemaname='organization_witness' ORDER BY tablename",
    )
    .fetch_all(&mut f.owner)
    .await?;
    let mut result = BTreeMap::new();
    for table in tables {
        let quoted = table.replace('"', "\"\"");
        let query = format!(
            "SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM organization_witness.\"{quoted}\" r"
        );
        result.insert(
            table,
            sqlx::query_scalar(&query).fetch_one(&mut f.owner).await?,
        );
    }
    Ok(result)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; read-only preflight preserves all durable state"]
async fn pg_organizations_startup_preflight_is_read_only_with_pending_work() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        sqlx::raw_sql(SEED).execute(&mut f.owner).await?;
        let before = snapshot(&mut f).await?;
        let mut runtime = f.connect(Role::Runtime).await?;
        sqlx::raw_sql("BEGIN READ ONLY")
            .execute(runtime.connection.as_mut().unwrap())
            .await?;
        let primary = json!({"cluster_id":1,"database_oid":1,
            "database_name":"startup_preflight_fixture","started_us":1,"timeline":1});
        let token = json!({"run_id":"d".repeat(40),"database":0});
        let expected = json!({
            "version":1,"deployment_id":scope().deployment_id,"environment_id":scope().environment_id,
            "parent":{"selection":selected(true),"primary_incarnation":primary,
                "token_incarnation":token,"minimum_wal":10},
            "child":{"selection":selected(false),"primary_incarnation":primary,
                "token_incarnation":token,"minimum_wal":20},
        });
        for _ in 0..70 {
            anyhow::ensure!(
                preflight(runtime.connection.as_mut().unwrap(), scope(), &selected(true), &selected(false)).await? == expected,
                "diagnostic output differs from the exact selected checkpoints"
            );
        }
        sqlx::raw_sql("ROLLBACK")
            .execute(runtime.connection.as_mut().unwrap())
            .await?;
        runtime.close().await?;
        anyhow::ensure!(before == snapshot(&mut f).await?, "preflight mutated durable state");
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; exact diagnostic scope, selection and checkpoint validation"]
async fn pg_organizations_startup_preflight_refuses_selection_and_checkpoint_drift() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        sqlx::raw_sql(SEED).execute(&mut f.owner).await?;
        let before = snapshot(&mut f).await?;
        let mut runtime = f.connect(Role::Runtime).await?;
        for parent in [true, false] {
            for key in ["epoch", "primary", "token_store", "source_sha256", "history_sha256", "acceptance_sha256"] {
                for replacement in [None, Some(Value::Null), Some(json!(1)), Some(json!("different"))] {
                    let mut changed = selected(parent);
                    if let Some(value) = replacement {
                        changed[key] = value;
                    } else {
                        changed.as_object_mut().unwrap().remove(key);
                    }
                    let (p, c) = if parent { (changed, selected(false)) } else { (selected(true), changed) };
                    anyhow::ensure!(preflight(runtime.connection.as_mut().unwrap(), scope(), &p, &c).await.is_err(), "changed selection accepted");
                }
            }
            for changed in [Value::Null, json!([]), { let mut value=selected(parent); value["extra"]=json!(true); value }] {
                let (p, c) = if parent { (changed, selected(false)) } else { (selected(true), changed) };
                anyhow::ensure!(preflight(runtime.connection.as_mut().unwrap(), scope(), &p, &c).await.is_err(), "malformed selection accepted");
            }
        }
        for changed in [
            Scope { deployment_id: Uuid::nil(), ..scope() },
            Scope { environment_id: Uuid::nil(), ..scope() },
            Scope { deployment_id: Uuid::new_v4(), ..scope() },
            Scope { environment_id: Uuid::new_v4(), ..scope() },
        ] {
            anyhow::ensure!(preflight(runtime.connection.as_mut().unwrap(), changed, &selected(true), &selected(false)).await.is_err(), "changed scope accepted");
        }
        runtime.close().await?;
        // Administrator-only corruption in a rollback-only test transaction.
        // These statements are not a reconciliation or repair procedure.
        for mutation in [
            "UPDATE organization_witness.deployments SET phase='fenced'",
            "UPDATE organization_witness.deployments SET phase='prepared'",
            "UPDATE organization_witness.authorities SET phase='fenced'",
            "UPDATE organization_witness.authorities SET phase='prepared'",
            "DELETE FROM organization_witness.deployment_children",
            "DELETE FROM organization_witness.store_observations; DELETE FROM organization_witness.store_checkpoints",
            "DELETE FROM organization_witness.deployment_store_observations; DELETE FROM organization_witness.deployment_store_seals; DELETE FROM organization_witness.deployment_store_checkpoints",
            "UPDATE organization_witness.store_checkpoints SET primary_id=gen_random_uuid()",
            "UPDATE organization_witness.deployment_store_checkpoints SET token_store_id=gen_random_uuid()",
            "UPDATE organization_witness.store_checkpoints SET primary_incarnation='{}'",
            "UPDATE organization_witness.deployment_store_checkpoints SET token_incarnation='{}'",
            "UPDATE organization_witness.store_checkpoints SET primary_incarnation=primary_incarnation||'{\"extra\":1}'",
            "UPDATE organization_witness.deployment_store_checkpoints SET primary_incarnation=primary_incarnation||'{\"wal_position\":10}'",
        ] {
            sqlx::raw_sql("BEGIN").execute(&mut f.owner).await?;
            sqlx::raw_sql(mutation).execute(&mut f.owner).await?;
            let refused = preflight(&mut f.owner, scope(), &selected(true), &selected(false)).await.is_err();
            sqlx::raw_sql("ROLLBACK").execute(&mut f.owner).await?;
            anyhow::ensure!(refused, "changed authority/checkpoint accepted: {mutation}");
        }
        anyhow::ensure!(before == snapshot(&mut f).await?, "refusal changed durable state");
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; runtime-only fixed diagnostic privilege"]
async fn pg_organizations_startup_preflight_preserves_least_privilege() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        sqlx::raw_sql(SEED).execute(&mut f.owner).await?;
        let mut runtime = f.connect(Role::Runtime).await?;
        for query in [
            "SELECT * FROM organization_witness.store_checkpoints",
            "SELECT * FROM organization_witness.deployment_store_checkpoints",
            "SELECT * FROM organization_witness.slots",
            "SELECT organization_witness.store_progress_pin(NULL,NULL,NULL,NULL,NULL,NULL)",
            "SELECT organization_witness.deployment_fence(NULL,NULL,NULL)",
            "SET ROLE aegaeon_organization_witness_owner",
        ] {
            anyhow::ensure!(sqlx::query(query).execute(runtime.connection.as_mut().unwrap()).await.is_err(), "unexpected runtime privilege");
        }
        runtime.close().await?;
        let mut maintenance = f.connect(Role::Maintenance).await?;
        anyhow::ensure!(preflight(maintenance.connection.as_mut().unwrap(), scope(), &selected(true), &selected(false)).await.is_err(), "maintenance executed runtime preflight");
        maintenance.close().await?;
        let properties: (String, bool, String, Vec<String>, bool) = sqlx::query_as(
            "SELECT provolatile::text,prosecdef,pg_get_userbyid(proowner),proconfig,NOT EXISTS(SELECT FROM aclexplode(COALESCE(proacl,acldefault('f',proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc WHERE oid='organization_witness.startup_preflight(uuid,uuid,jsonb,jsonb)'::regprocedure",
        ).fetch_one(&mut f.owner).await?;
        anyhow::ensure!(properties == ("s".into(),true,"aegaeon_organization_witness_owner".into(),vec!["search_path=pg_catalog, organization_witness".into()],true), "diagnostic catalog properties differ");
        // A role without membership has neither schema access nor EXECUTE.
        let outsider = format!("{}_outsider", f.runtime);
        sqlx::raw_sql(&format!("CREATE ROLE {outsider} NOLOGIN"))
            .execute(&mut f.owner).await?;
        let privilege: bool = sqlx::query_scalar("SELECT has_function_privilege($1,'organization_witness.startup_preflight(uuid,uuid,jsonb,jsonb)','EXECUTE')")
            .bind(&outsider).fetch_one(&mut f.owner).await?;
        sqlx::raw_sql(&format!("DROP ROLE {outsider}"))
            .execute(&mut f.owner).await?;
        anyhow::ensure!(!privilege, "unrelated role acquired EXECUTE");
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; forward migration requires drained fences"]
async fn pg_organizations_startup_preflight_migration_preserves_fenced_state() -> TestResult {
    let mut f = Fixture::with_version(14).await?;
    let result = async {
        sqlx::raw_sql(SEED).execute(&mut f.owner).await?;
        let schema = include_str!("../../../../../../db/organization-witness/schema-v15.sql");
        anyhow::ensure!(sqlx::raw_sql(schema).execute(&mut f.owner).await.is_err(), "migration accepted active/pending work");
        sqlx::raw_sql("ROLLBACK").execute(&mut f.owner).await?;
        // No actual worker was started: only this SQL fixture owns these rows.
        sqlx::raw_sql("UPDATE organization_witness.deployments SET phase='fenced'; UPDATE organization_witness.authorities SET phase='fenced'; UPDATE organization_witness.deployment_slots SET pending=false; UPDATE organization_witness.slots SET pending=false")
            .execute(&mut f.owner).await?;
        let before = snapshot(&mut f).await?;
        sqlx::raw_sql(schema).execute(&mut f.owner).await?;
        anyhow::ensure!(before == snapshot(&mut f).await?, "migration changed authority/history");
        let actual: Value = sqlx::query_scalar(include_str!(
            "../../../../../../db/organization-witness/catalog-v5.sql"
        ))
        .fetch_one(&mut f.owner)
        .await?;
        let expected: Value = serde_json::from_str(include_str!(
            "../../../../../../db/organization-witness/catalog-v15.json"
        ))?;
        anyhow::ensure!(actual == expected, "v15 migration catalog differs");
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}
