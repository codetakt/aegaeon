use crate::cli::Task;
#[cfg(not(feature = "openapi"))]
use std::env;
#[cfg(any(not(feature = "openapi"), test))]
use std::ffi::OsStr;
use std::{
    ffi::OsString,
    path::Path,
    process::{Command, ExitCode},
};

pub(crate) fn run(root: &Path, task: Task) -> anyhow::Result<ExitCode> {
    match task {
        Task::Help => {
            println!("{}", crate::cli::USAGE);
            Ok(ExitCode::SUCCESS)
        }
        Task::Dudect { profile } => replace(legacy_dudect_command(root, &profile)),
        Task::Kani(args) => replace(kani_command(root, args)),
        Task::Openapi { check } => run_openapi(root, check),
    }
}

fn legacy_dudect_command(root: &Path, profile: &str) -> Command {
    let mut command = Command::new("python3");
    command
        .arg(root.join("tests/constant_time/run_contract.py"))
        .args(["--adapter", "xtask", "--profile", profile])
        .current_dir(root);
    command
}

fn kani_command(root: &Path, args: Vec<OsString>) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(root.join("scripts/kani/run_kani.sh"))
        .args(args)
        .current_dir(root);
    command
}

#[cfg(feature = "openapi")]
fn run_openapi(root: &Path, check: bool) -> anyhow::Result<ExitCode> {
    crate::openapi::run(root, check)?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(feature = "openapi"))]
fn run_openapi(root: &Path, check: bool) -> anyhow::Result<ExitCode> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    replace(openapi_command(root, &cargo, check))
}

#[cfg(any(not(feature = "openapi"), test))]
fn openapi_command(root: &Path, cargo: &OsStr, check: bool) -> Command {
    let mut command = Command::new(cargo);
    command
        .args(["run", "--locked", "--manifest-path"])
        .arg(root.join("xtask/Cargo.toml"))
        .args([
            "--package",
            "xtask",
            "--bin",
            "xtask",
            "--features",
            "openapi",
        ])
        .args(["--", "openapi"])
        .current_dir(root);
    if check {
        command.arg("--check");
    }
    command
}

// Replace the dispatcher on Unix so its caller observes the child's original
// exit status and signal, including Kani and the single OpenAPI reexecution.
fn replace(mut command: Command) -> anyhow::Result<ExitCode> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(command.exec().into())
    }
    #[cfg(not(unix))]
    {
        let status = command.status()?;
        let code = status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .ok_or_else(|| {
                anyhow::anyhow!("Child exited without a portable exit code: {status}")
            })?;
        Ok(ExitCode::from(code))
    }
}

#[cfg(test)]
mod tests {
    use super::{kani_command, legacy_dudect_command, openapi_command};
    use std::{ffi::OsStr, path::Path};

    #[test]
    fn kani_command_keeps_exact_argv_and_root() {
        let root = Path::new("/repository with spaces");
        let args = ["--scope", "diagnostic", "--output", "a path", "$(literal)"];
        let command = kani_command(root, args.iter().map(Into::into).collect());
        let expected: Vec<_> =
            std::iter::once(root.join("scripts/kani/run_kani.sh").into_os_string())
                .chain(args.iter().map(Into::into))
                .collect();
        assert_eq!(command.get_program(), "bash");
        assert_eq!(command.get_args().collect::<Vec<_>>(), expected);
        assert_eq!(command.get_current_dir(), Some(root));
    }

    #[test]
    fn legacy_adapter_selects_only_the_existing_xtask_route() {
        let root = Path::new("/repository");
        let command = legacy_dudect_command(root, "periodic");
        assert_eq!(command.get_program(), "python3");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                root.join("tests/constant_time/run_contract.py").as_os_str(),
                OsStr::new("--adapter"),
                OsStr::new("xtask"),
                OsStr::new("--profile"),
                OsStr::new("periodic")
            ]
        );
        assert_eq!(command.get_current_dir(), Some(root));
    }

    #[test]
    fn openapi_bootstrap_enables_feature_once_and_preserves_check() {
        let root = Path::new("/repository with spaces");
        let command = openapi_command(root, OsStr::new("/pinned cargo"), true);
        assert_eq!(command.get_program(), "/pinned cargo");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("run"),
                OsStr::new("--locked"),
                OsStr::new("--manifest-path"),
                root.join("xtask/Cargo.toml").as_os_str(),
                OsStr::new("--package"),
                OsStr::new("xtask"),
                OsStr::new("--bin"),
                OsStr::new("xtask"),
                OsStr::new("--features"),
                OsStr::new("openapi"),
                OsStr::new("--"),
                OsStr::new("openapi"),
                OsStr::new("--check")
            ]
        );
        assert_eq!(command.get_current_dir(), Some(root));
    }

    #[cfg(unix)]
    #[test]
    fn process_replacement_preserves_exit_status_and_signal() -> anyhow::Result<()> {
        use std::{env, os::unix::process::ExitStatusExt, process::Command};
        if let Ok(mode) = env::var("XTASK_EXEC_CONTROL") {
            let script = match mode.as_str() {
                "exit" => "exit 37",
                "signal" => "kill -TERM $$",
                _ => anyhow::bail!("Invalid controlled subprocess mode"),
            };
            let mut child = Command::new("sh");
            child.args(["-c", script]);
            super::replace(child)?;
            anyhow::bail!("Successful Unix exec unexpectedly returned");
        }
        for (mode, code, signal) in [("exit", Some(37), None), ("signal", None, Some(15))] {
            let status = Command::new(env::current_exe()?)
                .args([
                    "--exact",
                    "tasks::tests::process_replacement_preserves_exit_status_and_signal",
                ])
                .env("XTASK_EXEC_CONTROL", mode)
                .status()?;
            assert_eq!(status.code(), code);
            assert_eq!(status.signal(), signal);
        }
        Ok(())
    }
}
