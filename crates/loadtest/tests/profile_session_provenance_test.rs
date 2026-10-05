//! Exercise real environment-based supplier admission in isolated child processes.
//! Every file and environment value below is a nonsecret reserved-domain fixture.

use aegaeon_loadtest::profile::{sha256, ClientProfile};
use serde_json::json;
use std::{error::Error, fs, path::PathBuf, process::Command};

type FixtureResult<T = ()> = Result<T, Box<dyn Error>>;

const ISSUER: &str = "https://issuer.example.test";
const SUBJECT: &str = "fixture-subject";
const SECRET: &str = "nonsecret-fixture-client-secret";
const COOKIE: &str = "aegaeon_auth_session=nonsecret-fixture-session";
const CHILD_CASE: &str = "AEGAEON_PROFILE_PROVENANCE_TEST_CASE";
const PROVENANCE_REJECTION: &str =
    "public-login receipt does not bind the supplied issuer/session/profile/subject";
const CASES: [&str; 6] = [
    "valid",
    "profile-digest",
    "session-digest",
    "issuer",
    "subject",
    "method",
];

fn profile_bytes() -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&json!({
        "issuer": ISSUER,
        "environment_id": "fixture-environment",
        "configuration_version_id": "fixture-version",
        "oauth_profile_id": "fixture-profile",
        "activation": "ACTIVE",
        "client_id": "fixture-client",
        "redirect_uri": "https://client.example.test/callback",
        "client_auth": "client_secret_post",
        "scope": "read offline_access",
        "oidc_scope": "openid",
        "subject": SUBJECT,
        "sender_policy": "dpop",
        "par_policy": "required",
        "resource": null,
        "id_token_alg": "RS256"
    }))
}

fn provenance_bytes(case: &str) -> FixtureResult<Vec<u8>> {
    let mut receipt = json!({
        "issuer": ISSUER,
        "subject": SUBJECT,
        "method": "public-login",
        "producer": "fixture-public-login-producer",
        "profile_sha256": sha256(&profile_bytes()?),
        // from_env removes the file's trailing newline before hashing the cookie.
        "session_sha256": sha256(COOKIE.as_bytes())
    });
    match case {
        "valid" => {}
        "profile-digest" => receipt["profile_sha256"] = json!("0".repeat(64)),
        "session-digest" => receipt["session_sha256"] = json!("1".repeat(64)),
        "issuer" => receipt["issuer"] = json!("https://other-issuer.example.test"),
        "subject" => receipt["subject"] = json!("other-fixture-subject"),
        "method" => receipt["method"] = json!("other-login-method"),
        _ => return Err("unknown controlled supplier case".into()),
    }
    serde_json::to_vec(&receipt).map_err(Into::into)
}

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn create() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "aegaeon-profile-provenance-{}",
            uuid::Uuid::new_v4()
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        Ok(Self(path))
    }

    fn cleanup(self) -> std::io::Result<()> {
        // Only this exclusively created directory and our fixed files are owned.
        fs::remove_dir_all(self.0)
    }
}

fn run_fixture_cases(owned: &FixtureDirectory) -> FixtureResult<Vec<(&'static str, bool, bool)>> {
    let manifest = owned.0.join("profile.json");
    let session = owned.0.join("session.txt");
    fs::write(&manifest, profile_bytes()?)?;
    fs::write(&session, format!("{COOKIE}\n"))?;
    let executable = std::env::current_exe()?;
    let mut outcomes = Vec::with_capacity(CASES.len());

    for case in CASES {
        let provenance = owned.0.join(format!("provenance-{case}.json"));
        fs::write(&provenance, provenance_bytes(case)?)?;
        let child = Command::new(&executable)
            .current_dir(&owned.0)
            .args([
                "--exact",
                "session_provenance_child_entry",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env(CHILD_CASE, case)
            .env("AEG_LOADTEST_PROFILE_MANIFEST", &manifest)
            .env("AEG_LOADTEST_CLIENT_SECRET", SECRET)
            .env("AEG_LOADTEST_SESSION_FILE", &session)
            .env("AEG_LOADTEST_SESSION_PROVENANCE", &provenance)
            .output()?;
        outcomes.push((
            case,
            child.status.success(),
            String::from_utf8_lossy(&child.stdout)
                .contains("test session_provenance_child_entry ... ok"),
        ));
    }
    Ok(outcomes)
}

#[test]
fn from_env_binds_session_provenance_in_isolated_children() -> FixtureResult {
    let owned = FixtureDirectory::create()?;
    let outcomes = run_fixture_cases(&owned);
    // Cleanup runs even when fixture I/O or child launch fails, and before any
    // assertion can unwind. Only our exclusively created directory is removed.
    let cleanup = owned.cleanup();
    let outcomes = outcomes?;
    cleanup?;
    for (case, success, selected_test_ran) in outcomes {
        // Never forward raw child output, supplier bytes or session/secret values.
        assert!(success, "supplier admission child failed: {case}");
        assert!(
            selected_test_ran,
            "child did not execute the selected supplier test: {case}"
        );
    }
    Ok(())
}

#[test]
#[ignore = "invoked exclusively by the env_clear parent supplier test"]
fn session_provenance_child_entry() -> FixtureResult {
    let Ok(case) = std::env::var(CHILD_CASE) else {
        return Err("controlled supplier case is required".into());
    };
    assert!(
        CASES.contains(&case.as_str()),
        "unknown controlled supplier case"
    );
    let result = ClientProfile::from_env(ISSUER, true, true);
    if case == "valid" {
        let Ok(profile) = result else {
            return Err("valid supplier fixture was rejected".into());
        };
        assert!(profile.supply.issuer == ISSUER && profile.supply.subject == SUBJECT);
        assert!(profile.secret == SECRET);
        assert!(profile.session_cookie.as_bytes() == COOKIE.as_bytes());
        assert!(profile.session_cookie.is_sensitive());
        assert!(profile.profile_sha256 == sha256(&profile_bytes()?));
        assert!(profile.session_provenance_sha256 == sha256(&provenance_bytes("valid")?));
    } else {
        let Err(error) = result else {
            return Err("mismatched supplier provenance was accepted".into());
        };
        assert!(
            error.to_string() == PROVENANCE_REJECTION,
            "invalid supplier fixture did not reach the exact provenance guard"
        );
    }
    Ok(())
}
