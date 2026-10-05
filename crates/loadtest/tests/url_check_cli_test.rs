//! Admission-only process controls; no server, services or workload execution.

use std::{
    ffi::OsStr,
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> std::io::Result<Self> {
        let root = std::env::temp_dir().join(format!("aegaeon-url-check-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root)?;
        let fixture = Self { root };
        fs::write(
            fixture.root.join("source-status.json"),
            b"preserved status\n",
        )?;
        Ok(fixture)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aegaeon-loadtest-url-check"));
        command
            .env_clear()
            .env("AEGAEON_DATABASE_URL", "synthetic-unusable")
            .env("AEG_LOADTEST_PROFILE_MANIFEST", "absent-profile.json")
            .env("AEG_LOADTEST_SESSION_FILE", "absent-session.json")
            .env("AEG_LOADTEST_SESSION_PROVENANCE", "absent-provenance.json")
            .current_dir(&self.root);
        command
    }

    fn unchanged(&self) -> std::io::Result<()> {
        assert_eq!(
            fs::read(self.root.join("source-status.json"))?,
            b"preserved status\n"
        );
        assert_eq!(fs::read_dir(&self.root)?.count(), 1);
        Ok(())
    }

    fn run(&self, arguments: &[impl AsRef<OsStr>]) -> std::io::Result<std::process::Output> {
        let result = self.command().args(arguments).output()?;
        self.unchanged()?;
        Ok(result)
    }

    fn config(&self, raw: &[u8]) -> std::io::Result<std::process::Output> {
        let mut child = self
            .command()
            .arg("--config-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("configuration stdin missing"))?
            .write_all(raw)?;
        let result = child.wait_with_output()?;
        self.unchanged()?;
        Ok(result)
    }
}

#[test]
fn configuration_preflight_uses_execution_invariants_without_effects() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let valid = serde_json::to_value(aegaeon_loadtest::LoadTestConfig::default())?;
    let positive = fixture.config(&serde_json::to_vec(&valid)?)?;
    assert!(positive.status.success());
    assert!(positive.stdout.is_empty() && positive.stderr.is_empty());
    for (field, value) in [
        ("workers", serde_json::json!(0)),
        ("workers", serde_json::json!(4_294_967_296_u64)),
        ("target_rps", serde_json::json!(0)),
        ("target_rps", serde_json::json!(1e20)),
        ("target_rps", serde_json::json!(1e-300)),
        ("duration", serde_json::json!({"secs":0,"nanos":0})),
        (
            "warmup_duration",
            serde_json::json!({"secs":86_401,"nanos":0}),
        ),
        ("scenario", serde_json::json!("Unknown")),
        (
            "target_url",
            serde_json::json!("https://user:synthetic-secret@issuer.example.test"),
        ),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        let result = fixture.config(&serde_json::to_vec(&invalid)?)?;
        assert_eq!(result.status.code(), Some(2), "{field}");
        assert!(result.stdout.is_empty());
        assert_eq!(result.stderr, b"[perf] configuration validation failed\n");
    }
    let mut boundary = valid.clone();
    boundary["workers"] = serde_json::json!(1);
    boundary["target_rps"] = serde_json::json!(1e9);
    assert!(fixture
        .config(&serde_json::to_vec(&boundary)?)?
        .status
        .success());
    for raw in [
        b"invalid synthetic-secret".to_vec(),
        b"{}".to_vec(),
        serde_json::to_vec(&serde_json::json!({"unknown":"synthetic-secret"}))?,
        vec![b' '; 65_537],
    ] {
        let result = fixture.config(&raw)?;
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert_eq!(result.stderr, b"[perf] configuration validation failed\n");
    }
    let extra = fixture.run(&["--config-stdin", "--url=http://localhost:8080"])?;
    assert_eq!(extra.status.code(), Some(2));
    assert_eq!(extra.stderr, b"[perf] configuration validation failed\n");
    Ok(())
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let cleanup = fs::remove_dir_all(&self.root);
        assert!(cleanup.is_ok(), "fixture cleanup failed: {cleanup:?}");
    }
}

#[test]
fn accepted_targets_and_canonical_issuers_exit_silently_without_files() -> std::io::Result<()> {
    let fixture = Fixture::new()?;
    for args in [
        vec!["--url", "http://localhost:8080"],
        vec![r"--url=https://issuer.example.test\tenant"],
        vec!["--url=https://issuer.example.test/https://fixture-secret"],
        vec!["--url=HTTPS://ISSUER.example.test:443/caf\u{00e9}"],
        vec!["--url", "https://[0:0:0:0:0:0:0:1]:443/tenant/"],
        vec![
            "--url",
            "http://127.0.0.1:18095",
            "--discovery-expected-issuer",
            "https://xn--bcher-kva.example.test/caf%C3%A9",
        ],
        vec![
            "--discovery-expected-issuer=https://[::1]:444/tenant",
            "--url=https://issuer.example.test",
        ],
    ] {
        let result = fixture.run(&args)?;
        assert!(result.status.success(), "{args:?}");
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }
    Ok(())
}

#[test]
fn invalid_inputs_and_cli_forms_fail_generically_without_files() -> std::io::Result<()> {
    let fixture = Fixture::new()?;
    for args in [
        vec![],
        vec!["--url"],
        vec!["--url="],
        vec!["--discovery-expected-issuer=https://issuer.example.test"],
        vec![
            "--url=http://localhost:8080",
            "--url=https://issuer.example.test",
        ],
        vec![
            "--url=http://localhost:8080",
            "--discovery-expected-issuer=https://issuer.example.test",
            "--discovery-expected-issuer=https://other.example.test",
        ],
        vec!["--url=https://user:synthetic-secret@issuer.example.test"],
        vec!["--url=https://@issuer.example.test"],
        vec!["--url=https://:synthetic-secret@issuer.example.test"],
        vec!["--url=https://user:@issuer.example.test"],
        vec!["--url=https://@/fixture-secret"],
        vec!["--url=https://user:synthetic-secret@/fixture-secret"],
        vec![r"--url=https://issuer.example.test\@fixture-secret"],
        vec!["--synthetic-secret=value"],
        vec![
            "--url=http://localhost:8080",
            "--report-file=synthetic-secret.json",
        ],
        vec![
            "--url=http://localhost:8080",
            "--discovery-expected-issuer=https://ISSUER.example.test",
        ],
        vec![
            "--url=http://localhost:8080",
            "--discovery-expected-issuer=https://issuer.example.test:443",
        ],
        vec![
            "--url=http://localhost:8080",
            "--discovery-expected-issuer=",
        ],
        vec!["--url=https://issuer.example.test:not-a-port"],
        vec!["--url=https:///fixture-secret"],
        vec!["--url=http:///fixture-secret"],
        vec!["--url=https:////fixture-secret"],
        vec![r"--url=https://\fixture-secret"],
        vec![r"--url=https://\\fixture-secret"],
        vec![r"--url=https:\\fixture-secret"],
        vec!["--url=https:/fixture-secret"],
        vec!["--url=https:fixture-secret"],
        vec!["--url=https:fixture://fixture-secret"],
        vec!["--url=http:fixture://fixture-secret"],
    ] {
        let result = fixture.run(&args)?;
        assert_eq!(result.status.code(), Some(2), "{args:?}");
        assert!(result.stdout.is_empty());
        assert_eq!(result.stderr, b"[perf] URL validation failed\n");
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_utf8_input_fails_generically() -> std::io::Result<()> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let fixture = Fixture::new()?;
    let result = fixture.run(&[OsString::from("--url"), OsString::from_vec(vec![0xff])])?;
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert_eq!(result.stderr, b"[perf] URL validation failed\n");
    Ok(())
}
