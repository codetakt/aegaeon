//! Only fixture provisioning. Every launch uses the separate release executable.
use super::*;
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};

#[tokio::test]
#[ignore = "requires the dedicated packaged TLS/browser runner"]
async fn dedicated_lti_packaged_prepare() -> Result {
    let directory = std::env::var("AEGAEON_LTI_PACKAGED_FIXTURE")?;
    let path = Path::new(&directory);
    let input: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("input.json"))?)?;
    let issuer = input["issuer_host"].as_str().ok_or("issuer host")?;
    let tool = input["tool"].as_str().ok_or("Tool origin")?;
    let mut fixture = Fixture::with_issuer(true, true, true, Some(issuer)).await?;
    fixture.config.initiate_login_uri = format!("{tool}/login");
    fixture.config.redirect_uris = [format!("{tool}/launch")].into();
    fixture.config.deployments[0].resource_links[0].target_link_uri = format!("{tool}/resource");
    fixture.replace(1).await?;
    let mut tx = fixture.state.db_pool.begin().await?;
    store::activate(&mut tx, fixture.state.environment_id, "tool", 2).await?;
    tx.commit().await?;
    let password = uuid::Uuid::new_v4().to_string();
    let hash = crate::local_credentials::hash_password(&password)?;
    sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash,status) VALUES($1,$2,'ACTIVE')")
        .bind(fixture.user).bind(hash).execute(&fixture.state.db_pool).await?;
    let output = json!({
        "issuer":fixture.state.issuer, "environment":fixture.state.environment_id,
        "user":fixture.user, "subject":"lti-user", "password":password, "tool":tool,
        "producer":"context-producer", "producer_secret":"test-lti-producer-secret",
    });
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path.join("fixture.json"))?;
    file.write_all(&serde_json::to_vec(&output)?)?;
    fixture.state.db_pool.close().await;
    Ok(())
}
