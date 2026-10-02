//! Offline operation; all SQL and artifact names are fixed by this implementation.
use super::artifacts::{file_identity, read_document, PrivateArtifacts};
use super::model::{Inventory, ToolSourceIdentity};
use super::preflight::{catalog_row_bound, verify_compiled_catalog};
use super::validation::{COLLECTIONS, INVENTORY_MAX_BYTES, MANIFEST_MAX_BYTES};
use super::{
    parse_inventory, parse_manifest, parse_strict, sha256_hex, validate_union, HashChain,
    HistoryInputError,
};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

type Result<T> = std::result::Result<T, HistoryInputError>;
fn refuse(reason: &'static str) -> HistoryInputError {
    HistoryInputError(reason.into())
}
#[derive(Parser)]
#[command(
    name = "aegaeon-subject-ownership",
    about = "Offline permanent subject history inventory and adoption"
)]
struct Command {
    #[command(subcommand)]
    operation: Operation,
}
#[derive(Subcommand)]
enum Operation {
    Inventory(InventoryArgs),
    Adopt(AdoptArgs),
}
#[derive(Args)]
struct Common {
    /// Connection URL; otherwise read the existing AEGAEON_DATABASE_URL setting.
    #[arg(long)]
    database_url: Option<String>,
    #[arg(long)]
    deployment_id: String,
    #[arg(long)]
    runtime_role: String,
    /// New private directory; previous attempts are never overwritten.
    #[arg(long)]
    output_dir: PathBuf,
    /// Reviewed source/build labels, including this executable's exact SHA256.
    #[arg(long)]
    tool_source_record: PathBuf,
    /// Exact retained dirty-source input record, when the build labels name one.
    #[arg(long)]
    dirty_input_record: Option<PathBuf>,
}
#[derive(Args)]
struct InventoryArgs {
    /// Inspect an unmigrated database using existing SELECT/lock authority.
    #[arg(long)]
    pre_migration: bool,
    #[command(flatten)]
    common: Common,
    #[arg(long)]
    environment_id: String,
}
#[derive(Args)]
struct AdoptArgs {
    #[command(flatten)]
    common: Common,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    inventory: PathBuf,
    /// Explicit local source mapping ID=PATH. Manifest references are never opened.
    #[arg(long = "source")]
    sources: Vec<String>,
    #[arg(long)]
    commit: bool,
    #[arg(long)]
    expected_manifest_sha256: Option<String>,
    #[arg(long)]
    expected_inventory_sha256: Option<String>,
}

/// Execute the offline CLI. Errors contain fixed operational text, never history.
pub async fn run() -> ExitCode {
    let command = Command::parse();
    let common = match &command.operation {
        Operation::Inventory(a) => &a.common,
        Operation::Adopt(a) => &a.common,
    };
    let output = match PrivateArtifacts::create(&common.output_dir) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let result = execute(&command.operation, &output).await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = output.write(
                "failure.json",
                &serde_json::to_vec(&json!({"status":"failed","reason":error.to_string()}))
                    .expect("fixed error JSON"),
            );
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn source_identity(common: &Common, output: &PrivateArtifacts) -> Result<ToolSourceIdentity> {
    let (raw, _) = read_document(&common.tool_source_record, 16 * 1024)?;
    let source: ToolSourceIdentity = serde_json::from_value(parse_strict(&raw, 16 * 1024)?)
        .map_err(|_| refuse("invalid tool source record"))?;
    let hex = |s: &str, n: usize| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if !hex(&source.tool_sha256, 64)
        || !hex(&source.source_tree, 40)
        || source.source_commit.as_ref().is_some_and(|s| !hex(s, 40))
        || source
            .dirty_input_sha256
            .as_ref()
            .is_some_and(|s| !hex(s, 64))
        || source.source_commit.is_none() && source.dirty_input_sha256.is_none()
    {
        return Err(refuse("invalid source/build identity"));
    }
    let executable =
        std::env::current_exe().map_err(|_| refuse("cannot identify running executable"))?;
    if file_identity(&executable)?.0 != source.tool_sha256 {
        return Err(refuse("executable does not match source/build record"));
    }
    match (&source.dirty_input_sha256, &common.dirty_input_record) {
        (Some(expected), Some(path)) => {
            let (input, hash) = read_document(path, MANIFEST_MAX_BYTES)?;
            if &hash != expected {
                return Err(refuse("dirty source input record digest mismatch"));
            }
            output.write("dirty-source-input.json", &input)?;
        }
        (None, None) => (),
        _ => {
            return Err(refuse(
                "dirty source input record does not match build labels",
            ))
        }
    }
    output.write("tool-source-record.json", &raw)?;
    Ok(source)
}

async fn transaction(common: &Common) -> Result<(sqlx::PgPool, Transaction<'static, Postgres>)> {
    let url = common
        .database_url
        .clone()
        .or_else(|| std::env::var("AEGAEON_DATABASE_URL").ok())
        .ok_or_else(|| refuse("database connection configuration is required"))?;
    let options = PgConnectOptions::from_str(&url)
        .map_err(|_| refuse("invalid database connection options"))?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|_| refuse("database connection failed"))?;
    let tx = pool
        .begin()
        .await
        .map_err(|_| refuse("database transaction failed"))?;
    Ok((pool, tx))
}

async fn execute(operation: &Operation, output: &PrivateArtifacts) -> Result<()> {
    match operation {
        Operation::Inventory(args) => execute_inventory(args, output).await,
        Operation::Adopt(args) => execute_adopt(args, output).await,
    }
}

async fn execute_inventory(args: &InventoryArgs, output: &PrivateArtifacts) -> Result<()> {
    let identity = source_identity(&args.common, output)?;
    let environment = uuid::Uuid::parse_str(&args.environment_id)
        .map_err(|_| refuse("invalid environment UUID"))?;
    if environment.to_string() != args.environment_id {
        return Err(refuse("environment UUID must be canonical"));
    }
    let (_pool, mut tx) = transaction(&args.common).await?;
    if args.pre_migration {
        super::pre_migration::collect(
            &mut tx,
            environment,
            &args.common.deployment_id,
            &args.common.runtime_role,
            &identity,
            output,
        )
        .await?;
        tx.rollback()
            .await
            .map_err(|_| refuse("pre-migration rollback failed"))?;
        let (hash, length) =
            file_identity(&args.common.output_dir.join("database-snapshot.jsonl"))?;
        output.write(
            "database-snapshot-identity.json",
            &serde_json::to_vec(&json!({
                "database_snapshot_sha256":hash,"database_snapshot_byte_length":length,
                "adoption_cas_eligible":false
            }))
            .expect("fixed snapshot identity"),
        )?;
        println!("Private pre-migration inventory retained; not adoption input.");
        return Ok(());
    }
    let inventory =
        collect_inventory(&mut tx, &args.common, environment, &identity, output).await?;
    let raw = serde_json::to_vec(&inventory).map_err(|_| refuse("cannot serialize inventory"))?;
    parse_inventory(&raw)?;
    output.write("inventory.json", &raw)?;
    tx.rollback()
        .await
        .map_err(|_| refuse("inventory rollback failed"))?;
    println!("Private inventory retained.");
    Ok(())
}

async fn execute_adopt(args: &AdoptArgs, output: &PrivateArtifacts) -> Result<()> {
    let identity = source_identity(&args.common, output)?;
    let (manifest_raw, manifest_hash) = read_document(&args.manifest, MANIFEST_MAX_BYTES)?;
    let (inventory_raw, inventory_hash) = read_document(&args.inventory, INVENTORY_MAX_BYTES)?;
    output.write("manifest.json", &manifest_raw)?;
    output.write("inventory.json", &inventory_raw)?;
    let manifest = parse_manifest(&manifest_raw)?;
    let inventory = parse_inventory(&inventory_raw)?;
    validate_union(&manifest, &inventory, &inventory_hash)?;
    if manifest.target.deployment_id != args.common.deployment_id
        || manifest.target.runtime_role != args.common.runtime_role
        || manifest.target.tool_sha256 != identity.tool_sha256
        || manifest.target.source_commit != identity.source_commit
        || manifest.target.source_tree != identity.source_tree
        || manifest.target.dirty_input_sha256 != identity.dirty_input_sha256
    {
        return Err(refuse(
            "command target or build labels differ from manifest",
        ));
    }
    if args.commit
        && (args.expected_manifest_sha256.as_deref() != Some(&manifest_hash)
            || args.expected_inventory_sha256.as_deref() != Some(&inventory_hash))
    {
        return Err(refuse(
            "commit requires both exact expected raw input hashes",
        ));
    }
    if args
        .expected_manifest_sha256
        .as_ref()
        .is_some_and(|h| h != &manifest_hash)
        || args
            .expected_inventory_sha256
            .as_ref()
            .is_some_and(|h| h != &inventory_hash)
    {
        return Err(refuse("expected raw input digest mismatch"));
    }
    let mappings: Result<Vec<_>> = args
        .sources
        .iter()
        .map(|mapping| {
            let (id, path) = mapping
                .split_once('=')
                .ok_or_else(|| refuse("source mapping must be ID=PATH"))?;
            Ok((id.to_owned(), PathBuf::from(path)))
        })
        .collect();
    output.retain_sources(&manifest, &mappings?)?;
    let environment = uuid::Uuid::parse_str(&manifest.namespace.environment_id)
        .map_err(|_| refuse("invalid manifest environment"))?;
    let (_pool, mut tx) = transaction(&args.common).await?;
    // The read-only entry acquires the same physical locks first. The
    // independently compiled checks complete before the import call.
    let actual = collect_inventory(&mut tx, &args.common, environment, &identity, output).await?;
    if serde_json::to_value(&actual).map_err(|_| refuse("inventory serialization failed"))?
        != serde_json::to_value(&inventory).map_err(|_| refuse("inventory serialization failed"))?
    {
        return Err(refuse("inventory differs from locked live state"));
    }
    let receipt=sqlx::query("SELECT pg_catalog.row_to_json(r)::text AS receipt FROM aegaeon.adopt_subject_ownership_history_v1($1,$2,$3,$4) r")
        .bind(&manifest_raw).bind(&inventory_raw).bind(&manifest_hash).bind(&inventory_hash).fetch_one(&mut *tx).await.map_err(|_| refuse("database refused history adoption"))?;
    let receipt: String = receipt
        .try_get("receipt")
        .map_err(|_| refuse("invalid adoption receipt"))?;
    output.write("transaction-receipt.json", receipt.as_bytes())?;
    output.recheck_sources(&manifest)?;
    if args.commit {
        tx.commit().await.map_err(|_| {
            refuse(
                "commit outcome is uncertain; inspect retained receipt and database before retry",
            )
        })?;
        output
            .write("disposition.json", br#"{"status":"committed"}"#)
            .map_err(|_| refuse("adoption committed but final disposition retention failed"))?;
        println!("History adoption committed; private receipt retained.");
    } else {
        tx.rollback()
            .await
            .map_err(|_| refuse("adoption rollback failed"))?;
        output.write(
            "disposition.json",
            br#"{"status":"validated-and-rolled-back"}"#,
        )?;
        println!("History adoption validated and rolled back.");
    }
    Ok(())
}

async fn collect_inventory(
    tx: &mut Transaction<'_, Postgres>,
    common: &Common,
    environment: uuid::Uuid,
    identity: &ToolSourceIdentity,
    output: &PrivateArtifacts,
) -> Result<Inventory> {
    let identity = serde_json::to_string(identity).map_err(|_| refuse("invalid build labels"))?;
    sqlx::query("DECLARE subject_history_inventory_cursor NO SCROLL CURSOR FOR SELECT record_type,row_key,payload FROM aegaeon.inventory_subject_ownership_history_v1($1,$2,$3,$4::jsonb)")
        .bind(environment).bind(&common.deployment_id).bind(&common.runtime_role).bind(identity).execute(&mut **tx).await.map_err(|_| refuse("database refused inventory"))?;
    let mut snapshot = output.new_file("database-snapshot.jsonl")?;
    let mut collections = Vec::new();
    let mut facts = Vec::new();
    let mut findings = Vec::new();
    let mut observed = None;
    let mut catalog = Vec::new();
    let mut bytes = 0usize;
    let mut chains: std::collections::HashMap<_, _> = COLLECTIONS
        .into_iter()
        .map(|name| (name, HashChain::new(name)))
        .collect();
    loop {
        let row = sqlx::query("FETCH FORWARD 1 FROM subject_history_inventory_cursor")
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| refuse("database inventory stream failed"))?;
        let Some(row) = row else {
            break;
        };
        let kind: String = row
            .try_get("record_type")
            .map_err(|_| refuse("invalid inventory stream record"))?;
        let key: String = row
            .try_get("row_key")
            .map_err(|_| refuse("invalid inventory stream key"))?;
        let text: String = row
            .try_get("payload")
            .map_err(|_| refuse("invalid inventory stream payload"))?;
        if kind.starts_with("source:") {
            retain_source_record(&kind, &key, &text, &mut snapshot, &mut chains, &mut catalog)?;
            continue;
        }
        bytes = bytes
            .checked_add(text.len() + key.len() + 64)
            .filter(|n| *n <= INVENTORY_MAX_BYTES)
            .ok_or_else(|| refuse("inventory exceeds supported document capacity"))?;
        let payload: Value =
            serde_json::from_str(&text).map_err(|_| refuse("invalid inventory record JSON"))?;
        match kind.as_str() {
            "collection" => collections.push(payload),
            "fact" => facts.push(payload),
            "finding" => findings.push(payload),
            "observed_target" => {
                if observed.replace(payload).is_some() {
                    return Err(refuse("duplicate observed inventory target"));
                }
            }
            _ => return Err(refuse("unknown inventory stream record")),
        }
    }
    sqlx::query("CLOSE subject_history_inventory_cursor")
        .execute(&mut **tx)
        .await
        .map_err(|_| refuse("cannot close inventory cursor"))?;
    snapshot
        .sync_all()
        .map_err(|_| refuse("cannot sync private database snapshot"))?;
    for collection in &collections {
        let name = collection["name"]
            .as_str()
            .ok_or_else(|| refuse("invalid collection name"))?;
        let (count, hash) = chains
            .remove(name)
            .ok_or_else(|| refuse("unexpected or duplicate collection"))?
            .finish();
        if collection["count"].as_u64() != Some(count)
            || collection["sha256"].as_str() != Some(super::digest::hex_digest(&hash).as_str())
        {
            return Err(refuse("SQL and Rust source collection digests differ"));
        }
    }
    if !chains.is_empty() {
        return Err(refuse("missing source collection"));
    }
    let target = observed.ok_or_else(|| refuse("missing observed inventory target"))?;
    verify_compiled_catalog(
        &catalog,
        target["target"]["schema_sha256"]
            .as_str()
            .ok_or_else(|| refuse("missing physical contract identity"))?,
        &common.runtime_role,
    )?;
    facts.sort_by(|a, b| a["fact_id"].as_str().cmp(&b["fact_id"].as_str()));
    findings.sort_by(|a, b| a["finding_id"].as_str().cmp(&b["finding_id"].as_str()));
    let value = json!({"format":"aegaeon-subject-ownership-inventory","version":1,"namespace":target["namespace"],"target":target["target"],"collections":collections,"state_sha256":target["state_sha256"],"facts":facts,"findings":findings,"findings_sha256":target["findings_sha256"]});
    let raw = serde_json::to_vec(&value).map_err(|_| refuse("inventory serialization failed"))?;
    let inventory = parse_inventory(&raw)?;
    let (snapshot_hash, snapshot_length) =
        file_identity(&common.output_dir.join("database-snapshot.jsonl"))?;
    output.write("database-snapshot-identity.json",&serde_json::to_vec(&json!({"database_snapshot_sha256":snapshot_hash,"database_snapshot_byte_length":snapshot_length,"inventory_document_sha256":sha256_hex(&raw)})).expect("snapshot identity serialization"))?;
    Ok(inventory)
}

fn retain_source_record(
    kind: &str,
    key: &str,
    text: &str,
    snapshot: &mut std::fs::File,
    chains: &mut std::collections::HashMap<&str, HashChain>,
    catalog: &mut Vec<(String, Value)>,
) -> Result<()> {
    let record = serde_json::to_vec(
        &json!({"collection":kind.trim_start_matches("source:"),"key":key,"row_text":text}),
    )
    .map_err(|_| refuse("source snapshot serialization failed"))?;
    snapshot
        .write_all(&record)
        .and_then(|()| snapshot.write_all(b"\n"))
        .map_err(|_| refuse("source snapshot retention failed"))?;
    chains
        .get_mut(kind.trim_start_matches("source:"))
        .ok_or_else(|| refuse("unknown source collection"))?
        .push(key, text.as_bytes())
        .map_err(|_| refuse("source collection exceeds supported row count"))?;
    if kind == "source:physical_catalog"
        && (key.starts_with("function:")
            || key.starts_with("atlas_revision:")
            || key.starts_with("role:"))
    {
        let value: Value =
            serde_json::from_str(text).map_err(|_| refuse("invalid physical catalog record"))?;
        if !key.starts_with("role:") || value["rolname"].as_str() == Some("aegaeon_subject_owner") {
            if catalog.len() >= catalog_row_bound() {
                return Err(refuse("unexpected physical function/revision inventory"));
            }
            catalog.push((key.to_owned(), value));
        }
    }
    Ok(())
}
