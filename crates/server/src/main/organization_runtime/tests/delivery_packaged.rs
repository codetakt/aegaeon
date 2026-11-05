//! Only independent store/bootstrap provisioning. The Python harness subsequently
//! uses actual packaged HTTP and CLI processes for every domain/client mutation.
use super::*;
use std::{io::Write, os::unix::fs::OpenOptionsExt};

#[test]
#[ignore = "requires independent TLS stores; prepares actual packaged delivery journey"]
fn organization_packaged_delivery_prepare() -> Result<()> {
    with_environment(tokio::runtime::Builder::new_current_thread(), || async {
        let mut context = super::fixture::prepare(true).await?;
        if std::env::var_os("AEGAEON_TEST_ORGANIZATION_CUTOVER_MULTIPLE").is_some() {
            super::fixture::add_environment(&mut context).await?;
        }
        if std::env::var_os("AEGAEON_TEST_ORGANIZATION_SNAPSHOT_FIXTURE").is_some() {
            super::snapshot_setup::retain(&context).await?;
        }
        context.prepared.startup.pool.close().await;
        context.control.close().await?;
        let input = PathBuf::from(std::env::var("AEGAEON_TEST_ORGANIZATION_STARTUP_FIXTURE")?);
        let mut document: serde_json::Value = serde_json::from_slice(&context.configuration)?;
        document["delivery_trust"] = serde_json::json!([{
            "origin":"https://delivery.example.test", "root_cert":document["primary"]["root_cert"]
        }]);
        let receipt = serde_json::json!({
            "team":context.initialized.team_id,"environment":context.initialized.environment_id,
            "configuration":context.initialized.configuration_version_id,
            "issuer_host":context.initialized.issuer_host,"issuer":context.issuer,
        });
        for (name, value) in [("runtime.json", document), ("bootstrap.json", receipt)] {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(input.with_file_name(name))?;
            file.write_all(&serde_json::to_vec(&value)?)?;
        }
        Ok(())
    })
}
