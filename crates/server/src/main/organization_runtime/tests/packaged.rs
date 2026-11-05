//! Current-generation schema launcher, release executable and Unix shutdown signals.
use super::*;
use reqwest::StatusCode;
use rustix::process::{kill_process, Pid, Signal};
use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
};

#[path = "packaged_snapshot.rs"]
mod snapshot;

struct Process(Child);
impl Process {
    async fn exit(&mut self, seconds: u64) -> Result<ExitStatus> {
        tokio::time::timeout(Duration::from_secs(seconds), async {
            loop {
                if let Some(status) = self.0.try_wait()? {
                    return Ok(status);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        // The outer fixture also owns the entire process group and its deadline.
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn start(
    binary: &Path,
    directory: &Path,
    label: &str,
    port: u16,
    issuer: &str,
    config: Option<&Path>,
) -> Result<Process> {
    let log = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(directory.join(format!("{label}.log")))?;
    let mut command = Command::new(binary);
    command
        .args(["--host", "127.0.0.1", "--port", &port.to_string()])
        .env("AEGAEON_RUNTIME_ISSUER_HOST", issuer)
        .env_remove("AEGAEON_ORGANIZATION_RUNTIME_CONFIG")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    if let Some(config) = config {
        command.env("AEGAEON_ORGANIZATION_RUNTIME_CONFIG", config);
    }
    Ok(Process(command.spawn()?))
}

#[test]
#[ignore = "requires packaged server and current PostgreSQL TLS supplier; owns actual child processes"]
fn organization_packaged_server_requires_configuration_and_drains_signals() -> Result<()> {
    with_environment(tokio::runtime::Builder::new_current_thread(), || async {
        let disabled =
            std::env::var("AEGAEON_TEST_ORGANIZATION_PACKAGED_DISABLED").as_deref() == Ok("1");
        crate::install_rustls_crypto_provider();
        let input = PathBuf::from(std::env::var("AEGAEON_TEST_ORGANIZATION_STARTUP_FIXTURE")?);
        let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(&input)?)?;
        use std::str::FromStr;
        let options =
            sqlx::postgres::PgConnectOptions::from_str(fixture["primary"].as_str().unwrap())?
                .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
                .ssl_root_cert(fixture["ca"].as_str().unwrap());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await?;
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(fixture["admin"].as_str().unwrap())
            .await?;
        use crate::web::management::initialization::{initialize_management, InitializationInput};
        let owner_password = format!("Fixture-{}-7!", Uuid::new_v4());
        let initialized = initialize_management(
            &pool,
            &InitializationInput {
                owner_email: "owner@example.test".into(),
                owner_password: owner_password.clone(),
                allowed_origins: vec!["https://admin.example.test".into()],
                issuer_base_domain: "example.test".into(),
            },
        )
        .await?;
        if !disabled {
            super::delivery_setup::enable_policy(&pool, &initialized).await?;
        }
        let snapshot_domain = if disabled {
            None
        } else {
            Some(snapshot::prepare(&pool, &initialized).await?)
        };
        pool.close().await;
        let deployment = Uuid::new_v4();
        let generation = Uuid::new_v4();
        sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,NULL,$2,$3)")
            .bind(deployment)
            .bind(generation)
            .bind(Uuid::new_v4())
            .execute(&admin)
            .await?;
        let configuration = serde_json::to_vec(&serde_json::json!({
            "version":2,"deployment_id":deployment,"generation":generation,
            "primary":{"url":fixture["primary"],"root_cert":fixture["ca"]},
            "environments":[{"id":initialized.environment_id,"issuer":format!("https://{}",initialized.issuer_host)}],
            "admission":{"ordinary":32,"revocation":2,"snapshot":1}
        }))?;
        let binary = PathBuf::from(std::env::var("AEGAEON_TEST_ORGANIZATION_SERVER")?);
        anyhow::ensure!(binary.is_absolute() && binary.is_file());
        let input = PathBuf::from(std::env::var("AEGAEON_TEST_ORGANIZATION_STARTUP_FIXTURE")?);
        let directory = input
            .parent()
            .ok_or_else(|| anyhow::anyhow!("fixture directory"))?;
        let config = directory.join("runtime.json");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&config)?;
        file.write_all(&configuration)?;
        drop(file);
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()?;
        let base = format!("http://127.0.0.1:{port}");
        let result = async {
            for (label, path) in [
                ("missing", None),
                ("empty", Some(Path::new(""))),
                ("relative", Some(Path::new("runtime.json"))),
            ] {
                let mut process = start(
                    &binary,
                    directory,
                    label,
                    port,
                    &initialized.issuer_host,
                    path,
                )?;
                anyhow::ensure!(
                    !process.exit(15).await?.success(),
                    "mandatory profile did not refuse {label}"
                );
                let log = std::fs::read_to_string(directory.join(format!("{label}.log")))?;
                anyhow::ensure!(
                    log.contains("independent Organizations runtime configuration is required"),
                    "unexpected {label} refusal"
                );
                anyhow::ensure!(tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_err());
            }
            for (label, signal) in [("term", Signal::TERM), ("int", Signal::INT)] {
                let mut process = start(
                    &binary,
                    directory,
                    label,
                    port,
                    &initialized.issuer_host,
                    Some(&config),
                )?;
                tokio::time::timeout(Duration::from_secs(30), async {
                    loop {
                        anyhow::ensure!(
                            process.0.try_wait()?.is_none(),
                            "packaged server exited before readiness; private log retained"
                        );
                        if client
                            .get(format!("{base}/health"))
                            .send()
                            .await
                            .is_ok_and(|v| v.status() == StatusCode::OK)
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Ok::<_, anyhow::Error>(())
                })
                .await??;
                for (path, status) in [
                    ("/ready".to_string(), StatusCode::NO_CONTENT),
                    ("/api/v1/system/version".to_string(), StatusCode::OK),
                    (
                        format!(
                            "/api/v1/teams/{}/environments/{}",
                            initialized.team_id, initialized.environment_id
                        ),
                        StatusCode::UNAUTHORIZED,
                    ),
                ] {
                    let response = client
                        .get(format!("{base}{path}"))
                        .header("x-forwarded-proto", "https")
                        .send()
                        .await?;
                    anyhow::ensure!(
                        response.status() == status,
                        "packaged route {path}: {}",
                        response.status()
                    );
                    let _ = response.bytes().await?;
                }
                if let Some(domain) = snapshot_domain {
                    snapshot::check(
                        &client,
                        &base,
                        &initialized,
                        domain,
                        &owner_password,
                        &admin,
                    )
                    .await?;
                }
                anyhow::ensure!(
                    sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4)")
                        .bind(deployment)
                        .bind(generation)
                        .bind(Uuid::new_v4())
                        .bind(Uuid::new_v4())
                        .execute(&admin)
                        .await
                        .is_err(),
                    "live packaged worker did not fence activation"
                );
                let pid = Pid::from_raw(i32::try_from(process.0.id())?)
                    .ok_or_else(|| anyhow::anyhow!("invalid child PID"))?;
                kill_process(pid, signal)?;
                anyhow::ensure!(
                    process.exit(55).await?.success(),
                    "packaged {label} shutdown failed"
                );
                anyhow::ensure!(tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_err());
                let count: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM aegaeon_lifecycle.activations")
                        .fetch_one(&admin)
                        .await?;
                anyhow::ensure!(count == 1, "ordinary restart changed the generation");
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        admin.close().await;
        result
    })
}
