//! Explicit inspection of a predecessor database; never an adoption CAS input.
use super::artifacts::PrivateArtifacts;
use super::model::ToolSourceIdentity;
use super::{content_id, frame, sha256_hex, HashChain, HistoryInputError};
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};
use std::{collections::HashSet, io::Write};
use uuid::Uuid;

mod classifier;
type Result<T> = std::result::Result<T, HistoryInputError>;
fn refuse(message: &'static str) -> HistoryInputError {
    HistoryInputError(message.into())
}
fn database_error(error: &sqlx::Error) -> HistoryInputError {
    if matches!(&error, sqlx::Error::Database(e) if e.code().as_deref()==Some("42501")) {
        refuse("pre-migration inventory requires existing SELECT and lock privileges; no elevation is performed")
    } else {
        refuse("pre-migration database inspection failed")
    }
}

pub(super) async fn collect(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    deployment: &str,
    runtime_role: &str,
    identity: &ToolSourceIdentity,
    output: &PrivateArtifacts,
) -> Result<()> {
    // Fixed inspection queries never mutate; SHARE locks freeze writers and partition DDL.
    // row_security=off produces an error when a caller would see filtered rows.
    sqlx::raw_sql("SET LOCAL search_path=pg_catalog,pg_temp; SET LOCAL row_security=off; SET LOCAL timezone='UTC'; SET LOCAL datestyle='ISO, YMD'; SET LOCAL intervalstyle='postgres'; SET LOCAL extra_float_digits=3; LOCK TABLE aegaeon.environments,aegaeon.end_users,aegaeon.audit_events IN SHARE MODE;")
        .execute(&mut **tx).await.map_err(|error| database_error(&error))?;
    let installed: bool=sqlx::query_scalar("SELECT to_regclass('aegaeon.subject_ownership_namespaces') IS NOT NULL OR to_regclass('aegaeon.subject_ownership_adoptions') IS NOT NULL OR to_regclass('aegaeon.end_user_identity_owners') IS NOT NULL OR to_regclass('aegaeon.end_user_subject_reservations') IS NOT NULL")
        .fetch_one(&mut **tx).await.map_err(|error| database_error(&error))?;
    if installed {
        return Err(refuse(
            "permanent ownership state exists; use normal inventory",
        ));
    }
    let filtered: bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_class WHERE oid IN ('aegaeon.environments'::regclass,'aegaeon.end_users'::regclass) AND (relrowsecurity OR relforcerowsecurity)) OR EXISTS(SELECT FROM pg_partition_tree('aegaeon.audit_events'::regclass) t JOIN pg_class c ON c.oid=t.relid WHERE c.relrowsecurity OR c.relforcerowsecurity)")
        .fetch_one(&mut **tx).await.map_err(|error| database_error(&error))?;
    if filtered {
        return Err(refuse("pre-migration source row security is unsupported"));
    }
    let target: String=sqlx::query_scalar("SELECT jsonb_build_object('database_name',current_database(),'database_oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'server_version_num',current_setting('server_version_num')::bigint,'server_encoding',current_setting('server_encoding'),'session_actor',session_user,'effective_actor',current_user)::text")
        .fetch_one(&mut **tx).await.map_err(|error| database_error(&error))?;
    let target: Value =
        serde_json::from_str(&target).map_err(|_| refuse("invalid inspection target"))?;
    if target["server_encoding"] != "UTF8" {
        return Err(refuse("pre-migration inventory requires UTF8 database"));
    }
    let mut snapshot = output.new_file("database-snapshot.jsonl")?;
    let mut facts = Vec::new();
    let mut findings = Vec::new();
    let mut environments = HashSet::new();
    let mut namespace = None;
    let mut collections = Vec::new();
    let mut output_bytes = 0usize;
    // Queries and columns are fixed. tableoid distinguishes duplicate audit IDs
    // across partitions; exact database JSON text is retained and digested.
    for (name,query) in [
        ("environments","DECLARE subject_pre_inventory NO SCROLL CURSOR FOR SELECT id::text AS row_key,to_jsonb(e)::text AS row_text FROM aegaeon.environments e ORDER BY id"),
        ("end_users","DECLARE subject_pre_inventory NO SCROLL CURSOR FOR SELECT id::text AS row_key,to_jsonb(u)::text AS row_text FROM aegaeon.end_users u ORDER BY id"),
        ("audit_events","DECLARE subject_pre_inventory NO SCROLL CURSOR FOR SELECT occurred_at::text AS occurred_at,id::text AS id,tableoid::text AS tableoid,to_jsonb(a)::text AS row_text FROM aegaeon.audit_events a ORDER BY occurred_at,id,tableoid"),
    ] {
        sqlx::query(query).execute(&mut **tx).await.map_err(|error| database_error(&error))?;
        let mut chain=HashChain::new(name);
        // Each fixed collection declares a different cursor row shape. Reusing a
        // prepared FETCH would retain the previous collection's column metadata.
        loop {
            let rows = sqlx::query("FETCH FORWARD 256 FROM subject_pre_inventory")
                .persistent(false).fetch_all(&mut **tx).await.map_err(|error| database_error(&error))?;
            if rows.is_empty() { break; }
            for row in rows {
            let key=if name=="audit_events" {
                let mut bytes=Vec::new();
                for field in ["occurred_at","id","tableoid"] {
                    let value: String=row.try_get(field).map_err(|_|refuse("invalid source key"))?;
                    bytes.extend(frame(value.as_bytes()));
                }
                super::digest::hex_digest(&bytes)
            } else { row.try_get("row_key").map_err(|_|refuse("invalid source key"))? };
            let text: String=row.try_get("row_text").map_err(|_|refuse("invalid source row"))?;
            chain.push(&key,text.as_bytes()).map_err(refuse)?;
            let value: Value=serde_json::from_str(&text).map_err(|_|refuse("invalid source JSON"))?;
            let record=serde_json::to_vec(&json!({"collection":name,"key":key,"row_text":text})).map_err(|_|refuse("snapshot serialization failed"))?;
            snapshot.write_all(&record).and_then(|()|snapshot.write_all(b"\n")).map_err(|_|refuse("snapshot retention failed"))?;
            if name=="environments" {
                let id=value["id"].as_str().ok_or_else(||refuse("invalid environment source"))?;
                environments.insert(id.to_owned());
                if id==environment.to_string() { namespace=Some(json!({"environment_id":id,"issuer_host":value["issuer_host"]})); }
            } else {
                let (new_facts,new_findings)=classifier::classify(name,&key,&text,&value,&environment.to_string(),&environments)?;
                output_bytes=output_bytes.checked_add(serde_json::to_vec(&(&new_facts,&new_findings)).map_err(|_|refuse("finding serialization failed"))?.len()).filter(|n|*n<=super::validation::INVENTORY_MAX_BYTES).ok_or_else(||refuse("pre-migration findings exceed supported capacity"))?;
                facts.extend(new_facts);findings.extend(new_findings);
            }
        }
        }
        sqlx::query("CLOSE subject_pre_inventory").execute(&mut **tx).await.map_err(|error| database_error(&error))?;
        let (count,hash)=chain.finish();collections.push(json!({"name":name,"count":count,"sha256":super::digest::hex_digest(&hash)}));
    }
    snapshot
        .sync_all()
        .map_err(|_| refuse("snapshot sync failed"))?;
    classifier::conflicts(&facts, &mut findings);
    facts.sort_by(|a, b| a["fact_id"].as_str().cmp(&b["fact_id"].as_str()));
    findings.sort_by(|a, b| a["finding_id"].as_str().cmp(&b["finding_id"].as_str()));
    let document = json!({"format":"aegaeon-subject-ownership-pre-migration-inventory","version":1,"permanent_state":"absent","adoption_cas_eligible":false,"namespace":namespace.ok_or_else(||refuse("target environment missing"))?,"target":target,"deployment_id":deployment,"runtime_role":runtime_role,"tool_source":identity,"collections":collections,"facts":facts,"findings":findings});
    let raw = serde_json::to_vec(&document)
        .map_err(|_| refuse("pre-migration inventory serialization failed"))?;
    if raw.len() > super::validation::INVENTORY_MAX_BYTES {
        return Err(refuse("pre-migration inventory exceeds supported capacity"));
    }
    output.write("pre-migration-inventory.json", &raw)?;
    output.write(
        "disposition.json",
        br#"{"status":"read-only-pre-migration-inspection","adoption_cas_eligible":false}"#,
    )?;
    Ok(())
}
