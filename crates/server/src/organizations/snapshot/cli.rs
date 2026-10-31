//! Separate inspection and inactive-preparation commands. Neither activates.
use super::{
    custody::{self, Artifacts},
    input::Input,
    staging,
};
use crate::organizations::Scope;
use clap::Parser;
use serde_json::json;
use sqlx::{
    postgres::{PgConnectOptions, PgSslMode},
    Connection, PgConnection,
};
use std::{
    io::{BufReader, Write},
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
    /// Inspect target references using this explicit runtime login's catalog.
    /// The database connection must use a separate maintenance login.
    #[arg(long)]
    target_runtime_role: Option<String>,
    /// Require current independent history under this exact drained recovery fence.
    #[arg(long, requires_all = ["target_runtime_role", "recovery_deployment_id", "recovery_revision", "witness_ca"])]
    recovery_operation_id: Option<Uuid>,
    #[arg(long, requires = "recovery_operation_id")]
    recovery_deployment_id: Option<Uuid>,
    #[arg(long, requires = "recovery_operation_id")]
    recovery_revision: Option<i64>,
    #[arg(long, requires = "recovery_operation_id")]
    witness_ca: Option<PathBuf>,
}

#[derive(Parser)]
#[command(
    name = "aegaeon-organization-import-prepare",
    about = "Prepare a new inactive Organizations scope; never activate it"
)]
struct PrepareCommand {
    #[command(flatten)]
    input: Command,
    #[arg(long, requires = "target_runtime_role")]
    operation_id: Uuid,
}

/// Run under an independent process deadline as documented; the async deadline
/// below also bounds network/SQL waits, but cannot interrupt blocked filesystem I/O.
pub async fn run() -> ExitCode {
    run_command(Command::parse(), None).await
}

/// Explicit maintenance mutation, separate from the read-only inspector.
pub async fn run_prepare() -> ExitCode {
    let command = PrepareCommand::parse();
    run_command(command.input, Some(command.operation_id)).await
}

async fn run_command(command: Command, operation: Option<Uuid>) -> ExitCode {
    let output = match Artifacts::create(&command.output_dir) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let result = tokio::time::timeout(
        Duration::from_secs(OPERATION_SECONDS),
        execute(&command, &output, operation),
    )
    .await
    .map_err(|_| "import operation deadline exceeded".to_string())
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

async fn execute(command: &Command, output: &Artifacts, operation: Option<Uuid>) -> Result<()> {
    if operation.is_some() && command.recovery_operation_id.is_some() {
        return Err(
            "recovery history comparison is read-only; inactive preparation is separate".into(),
        );
    }
    let source = custody::identity::tool_source(
        &command.tool_source_record,
        command.dirty_input_record.as_deref(),
        output,
    )?;
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
    let connection = connect(operation.is_some()).await?;
    let inspection = match (operation, command.target_runtime_role.as_deref()) {
        (Some(operation), Some(runtime)) => {
            staging::prepare::inactive(connection, input, runtime, operation)
                .await
                .map_err(|e| e.to_string())?
        }
        (Some(_), None) => {
            return Err("inactive preparation requires an explicit runtime role".into())
        }
        (None, runtime) => {
            let inspection = match runtime {
                None => staging::inspect_source(connection, input).await,
                Some(runtime) => match command.recovery_operation_id {
                    None => staging::inspect_target(connection, input, runtime).await,
                    Some(operation_id) => {
                        use crate::organizations::witness::{Control, Role, Scope};
                        let deployment_id = command
                            .recovery_deployment_id
                            .ok_or("recovery deployment required")?;
                        let revision = command
                            .recovery_revision
                            .ok_or("recovery revision required")?;
                        let ca = command.witness_ca.as_deref().ok_or("witness CA required")?;
                        let endpoint = std::env::var("AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL")
                            .map_err(|_| "witness endpoint required")?;
                        let control = Control::connect(&endpoint, ca, Role::Maintenance)
                            .await
                            .map_err(|_| "recovery witness connection refused")?;
                        let fence = staging::recovery::Fence {
                            scope: Scope {
                                environment_id: command.environment_id,
                                deployment_id,
                            },
                            operation_id,
                            revision,
                        };
                        staging::recovery::inspect(connection, control, input, runtime, fence).await
                    }
                },
            }
            .map_err(|e| e.to_string())?;
            serde_json::to_value(inspection).map_err(|_| "inspection serialization".to_string())?
        }
    };
    let kind = if operation.is_some() {
        "organization-inactive-preparation"
    } else if command.recovery_operation_id.is_some() {
        "organization-recovery-history-inspection"
    } else if command.target_runtime_role.is_some() {
        "organization-target-preflight"
    } else {
        "organization-source-inspection"
    };
    let receipt = json!({"version":1,"kind":kind,"toolSource":source,"inspection":inspection});
    let bytes = serde_json::to_vec(&receipt).map_err(|_| "receipt serialization".to_string())?;
    output
        .complete(&mut retained, &command.expected_sha256, &bytes)
        .map_err(|e| e.to_string())?;
    writeln!(
        std::io::stdout().lock(),
        "{}",
        json!({"status":kind,"durablyRetained":true,"sha256":command.expected_sha256,"targetDependenciesChecked":false,"activationAuthorized":false})
    ).map_err(|_| "receipt retained; stdout delivery failed".to_string())?;
    Ok(())
}

async fn connect(preparing: bool) -> Result<PgConnection> {
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
    let application = if preparing {
        "aegaeon-organization-import-prepare"
    } else {
        "aegaeon-organization-import-inspect"
    };
    let mut connection = tokio::time::timeout(
        Duration::from_secs(10),
        PgConnection::connect_with(&options.application_name(application)),
    )
    .await
    .map_err(|_| "database connection deadline".to_string())?
    .map_err(|_| "database connection failed".to_string())?;
    tokio::time::timeout(Duration::from_secs(5), sqlx::query("SELECT set_config(name,LEAST(COALESCE(NULLIF(setting::bigint,0),budget),budget)::text,false) FROM pg_settings JOIN (VALUES ('statement_timeout',5000::bigint),('lock_timeout',1000::bigint),('idle_in_transaction_session_timeout',30000::bigint),('transaction_timeout',3600000::bigint)) AS limits(name,budget) USING(name)").execute(&mut connection)).await
        .map_err(|_| "database budget setup deadline".to_string())?.map_err(|_| "database budget setup failed".to_string())?;
    Ok(connection)
}
