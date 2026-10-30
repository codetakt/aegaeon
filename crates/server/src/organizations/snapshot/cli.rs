//! Offline source inspection only. No activation/adoption command is exposed.
use super::{
    custody::{self, Artifacts},
    input::Input,
    staging,
};
use crate::organizations::Scope;
use crate::subject_ownership::history::{
    artifacts::file_identity, model::ToolSourceIdentity, parse_strict, sha256_hex,
};
use clap::Parser;
use serde_json::json;
use sqlx::{
    postgres::{PgConnectOptions, PgSslMode},
    Connection, PgConnection,
};
use std::{
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    time::Duration,
};
use uuid::Uuid;

mod connection;

type Result<T> = std::result::Result<T, String>;
const OPERATION_SECONDS: u64 = 3600;

#[derive(Parser)]
#[command(
    name = "aegaeon-organization-import-inspect",
    about = "Inspect a retained Organizations source in private, read-only staging; never activate it"
)]
struct Command {
    #[arg(long)]
    snapshot: PathBuf,
    #[arg(long)]
    expected_sha256: String,
    #[arg(long)]
    environment_id: Uuid,
    #[arg(long)]
    domain_id: Uuid,
    /// New child under a private owned parent (0700), with at most 64 entries.
    #[arg(long)]
    output_dir: PathBuf,
    /// Reviewed labels including the exact executable SHA-256.
    #[arg(long)]
    tool_source_record: PathBuf,
    #[arg(long)]
    dirty_input_record: Option<PathBuf>,
}

/// Run under an independent process deadline as documented; the async deadline
/// below also bounds network/SQL waits, but cannot interrupt blocked filesystem I/O.
pub async fn run() -> ExitCode {
    let command = Command::parse();
    let output = match Artifacts::create(&command.output_dir) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let result = tokio::time::timeout(
        Duration::from_secs(OPERATION_SECONDS),
        execute(&command, &output),
    )
    .await
    .map_err(|_| "inspection deadline exceeded".to_string())
    .and_then(|result| result);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let failure = json!({"status":"failed","reason":error,"activationAuthorized":false});
            let _ = output.write("failure.json", failure.to_string().as_bytes());
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(command: &Command, output: &Artifacts) -> Result<()> {
    let source = tool_source(command, output)?;
    let mut retained = output
        .retain(&command.snapshot, &command.expected_sha256)
        .map_err(|e| e.to_string())?;
    let input_file = retained
        .try_clone()
        .map_err(|_| "retained input descriptor".to_string())?;
    let input = Input::new(
        BufReader::with_capacity(65536, input_file),
        Scope {
            environment_id: command.environment_id,
            domain_id: command.domain_id,
        },
        &command.expected_sha256,
    )
    .map_err(|e| e.to_string())?;
    let connection = connect().await?;
    let inspection = staging::inspect_source(connection, input)
        .await
        .map_err(|e| e.to_string())?;
    let receipt = json!({"version":1,"kind":"organization-source-inspection","toolSource":source,"inspection":inspection});
    let bytes = serde_json::to_vec(&receipt).map_err(|_| "receipt serialization".to_string())?;
    output
        .complete(&mut retained, &command.expected_sha256, &bytes)
        .map_err(|e| e.to_string())?;
    writeln!(
        std::io::stdout().lock(),
        "{}",
        json!({"status":"source-inspected","durablyRetained":true,"sha256":command.expected_sha256,"targetDependenciesChecked":false,"activationAuthorized":false})
    ).map_err(|_| "receipt retained; stdout delivery failed".to_string())?;
    Ok(())
}

fn read_private(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    custody::open_private(path, maximum)
        .map_err(|e| e.to_string())?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "private metadata read".to_string())?;
    if bytes.len() as u64 > maximum {
        return Err("private metadata byte limit".into());
    }
    Ok(bytes)
}

fn tool_source(command: &Command, output: &Artifacts) -> Result<ToolSourceIdentity> {
    let raw = read_private(&command.tool_source_record, 16384)?;
    let value = parse_strict(&raw, 16384).map_err(|_| "tool source record syntax".to_string())?;
    let source: ToolSourceIdentity =
        serde_json::from_value(value).map_err(|_| "tool source record shape".to_string())?;
    let git = |s: &str| {
        s.len() == 40
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if !custody::valid_digest(&source.tool_sha256)
        || !git(&source.source_tree)
        || source.source_commit.as_ref().is_some_and(|s| !git(s))
        || source
            .dirty_input_sha256
            .as_ref()
            .is_some_and(|s| !custody::valid_digest(s))
        || source.source_commit.is_none() && source.dirty_input_sha256.is_none()
    {
        return Err("tool source labels invalid".into());
    }
    let executable = std::env::current_exe().map_err(|_| "executable identity".to_string())?;
    if std::fs::metadata(&executable)
        .map_err(|_| "executable metadata".to_string())?
        .len()
        > 1024 * 1024 * 1024
        || file_identity(&executable)
            .map_err(|_| "executable hash".to_string())?
            .0
            != source.tool_sha256
    {
        return Err("executable differs from reviewed source record".into());
    }
    match (&source.dirty_input_sha256, &command.dirty_input_record) {
        (Some(expected), Some(path)) => {
            let bytes = read_private(path, 1024 * 1024)?;
            if sha256_hex(&bytes) != *expected {
                return Err("dirty source record digest mismatch".into());
            }
            output
                .write("dirty-source-input.json", &bytes)
                .map_err(|e| e.to_string())?;
        }
        (None, None) => (),
        _ => return Err("dirty source record must exactly match build labels".into()),
    }
    output
        .write("tool-source-record.json", &raw)
        .map_err(|e| e.to_string())?;
    Ok(source)
}

async fn connect() -> Result<PgConnection> {
    if std::env::vars_os().any(|(key, _)| key.to_string_lossy().starts_with("PG")) {
        return Err("ambient PostgreSQL connection settings are not allowed".into());
    }
    let url = std::env::var("AEGAEON_DATABASE_URL")
        .map_err(|_| "AEGAEON_DATABASE_URL is required".to_string())?;
    let url = connection::explicit_url(&url)?;
    let mut options =
        PgConnectOptions::from_str(&url).map_err(|_| "database connection options".to_string())?;
    let socket = options.get_socket().map(PathBuf::as_path).or_else(|| {
        options
            .get_host()
            .starts_with('/')
            .then(|| Path::new(options.get_host()))
    });
    options = if let Some(directory) = socket {
        custody::private_socket_directory(directory).map_err(|e| e.to_string())?;
        options.ssl_mode(PgSslMode::Disable)
    } else {
        options.ssl_mode(PgSslMode::VerifyFull)
    };
    let mut connection = tokio::time::timeout(
        Duration::from_secs(10),
        PgConnection::connect_with(
            &options.application_name("aegaeon-organization-import-inspect"),
        ),
    )
    .await
    .map_err(|_| "database connection deadline".to_string())?
    .map_err(|_| "database connection failed".to_string())?;
    tokio::time::timeout(Duration::from_secs(5), sqlx::query("SELECT set_config(name,LEAST(COALESCE(NULLIF(setting::bigint,0),budget),budget)::text,false) FROM pg_settings JOIN (VALUES ('statement_timeout',5000::bigint),('lock_timeout',1000::bigint),('idle_in_transaction_session_timeout',30000::bigint),('transaction_timeout',3600000::bigint)) AS limits(name,budget) USING(name)").execute(&mut connection)).await
        .map_err(|_| "database budget setup deadline".to_string())?.map_err(|_| "database budget setup failed".to_string())?;
    Ok(connection)
}
