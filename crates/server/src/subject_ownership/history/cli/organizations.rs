//! Explicit offline ownership maintenance against one selected database.
use super::*;
use crate::organizations::lifecycle::Selection;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "aegaeon-organization-subject-ownership")]
struct OrganizationCommand {
    #[arg(long)]
    generation: Uuid,
    #[arg(long)]
    primary_ca: PathBuf,
    #[command(subcommand)]
    operation: Operation,
}

pub async fn run() -> ExitCode {
    let mut command = OrganizationCommand::parse();
    let output = match PrivateArtifacts::create(&command.operation.common().output_dir) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        anyhow::ensure!(!matches!(&command.operation,Operation::Inventory(args) if args.pre_migration),
            "pre-migration inventory uses the preactivation entry");
        let deployment = Uuid::parse_str(&command.operation.common().deployment_id)?;
        let selected = Selection::new(deployment, command.generation)?;
        match &mut command.operation {
            Operation::Inventory(args) => args.common.lifecycle=Some(selected),
            Operation::Adopt(args) => args.common.lifecycle=Some(selected),
        }
        let prepared = prepare(&command.operation,&output)?;
        output.write("selected-runtime.json",serde_json::to_vec(&json!({"version":2,"deploymentId":deployment,
            "generation":command.generation,"kind":command.operation.kind(),"activationAuthorized":false}))?.as_slice())?;
        execute(&command.operation,&prepared,&output,Some(&command.primary_ca)).await?;
        Ok::<_,anyhow::Error>(())
    }).await;
    if matches!(result, Ok(Ok(()))) {
        println!("Subject ownership operation completed; private receipt retained.");
        ExitCode::SUCCESS
    } else {
        let reason = if result.is_err() {
            "operation deadline"
        } else {
            "operation refused or unconfirmed"
        };
        let _ = output.write(
            "failure.json",
            json!({"status":"failed","reason":reason})
                .to_string()
                .as_bytes(),
        );
        eprintln!("Organizations subject ownership {reason}");
        ExitCode::FAILURE
    }
}
