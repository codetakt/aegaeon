use std::ffi::OsString;

pub(crate) const USAGE: &str =
    "usage: cargo xtask {dudect|kani [ARGS...]|openapi [--check]|--help}";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Task {
    Help,
    Dudect,
    Kani(Vec<OsString>),
    Openapi { check: bool },
}

pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> anyhow::Result<Task> {
    let mut args = args.into_iter();
    let command = args.next().ok_or_else(|| anyhow::anyhow!("Missing task"))?;
    if command == "kani" {
        return Ok(Task::Kani(args.collect()));
    }
    let remaining: Vec<_> = args.collect();
    match command.to_str() {
        Some("--help" | "-h") if remaining.is_empty() => Ok(Task::Help),
        Some("dudect") if remaining.is_empty() => Ok(Task::Dudect),
        Some("openapi") if remaining.iter().all(|arg| arg == "--check") => Ok(Task::Openapi {
            check: !remaining.is_empty(),
        }),
        _ => anyhow::bail!(
            "Invalid task or arguments: {} {remaining:?}",
            command.to_string_lossy()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, Task};
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn syntax_errors_are_rejected_before_dispatch() {
        for values in [
            &[][..],
            &["unknown"],
            &["dudect", "--scope", "partial"],
            &["openapi", "--unknown"],
            &["--help", "extra"],
        ] {
            assert!(parse(args(values)).is_err(), "{values:?}");
        }
    }

    #[test]
    fn help_and_openapi_compatibility_are_explicit() -> anyhow::Result<()> {
        assert_eq!(parse(args(&["--help"]))?, Task::Help);
        assert_eq!(parse(args(&["-h"]))?, Task::Help);
        assert_eq!(parse(args(&["dudect"]))?, Task::Dudect);
        assert_eq!(parse(args(&["openapi"]))?, Task::Openapi { check: false });
        // The original parser accepted repeated --check flags.
        assert_eq!(
            parse(args(&["openapi", "--check", "--check"]))?,
            Task::Openapi { check: true }
        );
        Ok(())
    }

    #[test]
    fn kani_keeps_scope_groups_and_os_arguments() -> anyhow::Result<()> {
        let forwarded = args(&["--scope", "partial", "--groups", "ffi-evidence"]);
        let input = std::iter::once(OsString::from("kani")).chain(forwarded.clone());
        assert_eq!(parse(input)?, Task::Kani(forwarded));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let raw = OsString::from_vec(vec![0xff]);
            assert_eq!(
                parse([OsString::from("kani"), raw.clone()])?,
                Task::Kani(vec![raw])
            );
        }
        Ok(())
    }
}
