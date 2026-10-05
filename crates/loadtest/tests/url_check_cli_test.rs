//! URL-only process controls; no server, services, builds inside the utility or workload.

use std::{ffi::OsStr, fs, path::PathBuf, process::Command};

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

    fn run(&self, arguments: &[impl AsRef<OsStr>]) -> std::io::Result<std::process::Output> {
        let result = Command::new(env!("CARGO_BIN_EXE_aegaeon-loadtest-url-check"))
            .args(arguments)
            .env_clear()
            .env("AEGAEON_DATABASE_URL", "synthetic-unusable")
            .env("AEG_LOADTEST_PROFILE_MANIFEST", "absent-profile.json")
            .env("AEG_LOADTEST_SESSION_FILE", "absent-session.json")
            .env("AEG_LOADTEST_SESSION_PROVENANCE", "absent-provenance.json")
            .current_dir(&self.root)
            .output()?;
        assert_eq!(
            fs::read(self.root.join("source-status.json"))?,
            b"preserved status\n"
        );
        assert_eq!(fs::read_dir(&self.root)?.count(), 1);
        Ok(result)
    }
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
