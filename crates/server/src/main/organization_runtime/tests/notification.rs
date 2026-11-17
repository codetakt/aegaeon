//! Current production construction and polling on real restricted PostgreSQL.
//! The only transport substitution is the existing local TLS trust/DNS fixture.
use super::*;
use crate::organizations::{
    invitations::transport::fixture::Fixture as TransportFixture,
    notification_worker::Configuration as WorkerConfiguration,
    operators::mutations::delivery::Encryption,
};
use crate::web::management::initialization::{initialize_management, InitializationInput};
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeySize, PrivateDecryptingKey},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path, str::FromStr};
use zeroize::Zeroizing;

fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

// Preserve setup errors in the private fixture capture. The worker below still
// uses Prepared::build, including the production startup/redaction boundary.
async fn build_issuing_fixture(
    prepared: Prepared,
) -> Result<(BuiltServerRuntime, EnvironmentDispatcher)> {
    let Prepared {
        issuer_host,
        bootstrap,
        startup,
        dispatcher,
        ..
    } = prepared;
    let pool = startup.pool.clone();
    let result = match dispatcher.startup_preflight(move || async move {
        build_server_runtime_with_inputs(issuer_host, bootstrap, Some(startup)).await
    }) {
        Ok(execution) => execution.result().await,
        Err(error) => Err(error),
    };
    if !matches!(&result, Ok(Ok(_))) {
        dispatcher.deployment().close().await;
        crate::organizations::lifecycle::close_pool(&pool).await;
    }
    Ok((result??, dispatcher))
}

async fn exercise(once: bool, lose_reply: bool) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    crate::install_rustls_crypto_provider();
    let path = PathBuf::from(std::env::var("AEGAEON_TEST_ORGANIZATION_STARTUP_FIXTURE")?);
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let options = sqlx::postgres::PgConnectOptions::from_str(fixture["primary"].as_str().unwrap())?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(fixture["ca"].as_str().unwrap());
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(fixture["admin"].as_str().unwrap())
        .await?;
    let result = async {
        let initialized = initialize_management(&pool, &InitializationInput {
            owner_email: "owner@example.test".into(),
            owner_password: format!("Fixture-{}-7!", Uuid::new_v4()),
            allowed_origins: vec!["https://admin.example.test".into()],
            issuer_base_domain: "example.test".into(),
        }).await?;
        super::delivery_setup::enable_policy(&pool, &initialized).await?;
        let environment = initialized.environment_id;
        if lose_reply {
            sqlx::query("UPDATE aegaeon.environments SET organization_identity_policy=$2 WHERE id=$1")
                .bind(environment)
                .bind(serde_json::json!({"registration":true,"passwordRecovery":false,"subjectFormat":"uuid"}))
                .execute(&pool).await?;
        }
        let issuer = format!("https://{}", initialized.issuer_host);
        let deployment = Uuid::new_v4();
        let generation = Uuid::new_v4();
        sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,NULL,$2,$3)")
            .bind(deployment).bind(generation).bind(Uuid::new_v4()).execute(&admin).await?;
        let configuration = serde_json::to_vec(&serde_json::json!({
            "version":2,"deployment_id":deployment,"generation":generation,
            "primary":{"url":fixture["primary"],"root_cert":fixture["ca"]},
            "environments":[{"id":environment,"issuer":issuer}],
            "admission":{"ordinary":8,"revocation":2,"snapshot":1}
        }))?;
        let config_path = path.with_file_name("notification-runtime.json");
        private_file(&config_path, &configuration)?;
        let _config = EnvVarGuard::new("AEGAEON_ORGANIZATION_RUNTIME_CONFIG", config_path.to_str());
        let _issuer = EnvVarGuard::new("AEGAEON_RUNTIME_ISSUER_HOST", Some(&initialized.issuer_host));
        let now = i64::try_from(crate::util::now_unix_epoch_secs()?)?;
        let key = PrivateDecryptingKey::generate(KeySize::Rsa2048)?;
        let public = key.public_key().as_der()?;
        let pin = URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(public.as_ref()));
        let encryption = Encryption {
            version: "worker_test_1".into(), deployment_id: deployment,
            public_spki: URL_SAFE_NO_PAD.encode(public.as_ref()), spki_sha256: pin.clone(),
            not_before: now - 10, seal_until: now + 7200, open_until: now + 14400,
        };
        let private = Zeroizing::new(serde_json::to_vec(&serde_json::json!({
            "version":1,"credential":super::delivery_setup::credential(),
            "keys":[{"version":encryption.version,"deployment_id":deployment,
                "scope":{"kind":"environment","environment_id":environment},
                "not_before":encryption.not_before,"seal_until":encryption.seal_until,
                "open_until":encryption.open_until,"spki_sha256":pin,
                "pkcs8":URL_SAFE_NO_PAD.encode(key.as_der()?.as_ref())}]
        }))?);
        let key_path = path.with_file_name("notification-keys.json");
        private_file(&key_path, &private)?;
        let prepared = Prepared::from_environment().await?;
        let trust = prepared.delivery_trust.clone();
        let (runtime, dispatcher) = build_issuing_fixture(prepared).await?;
        let state = runtime.state.clone();
        let (domain, invitation) = dispatcher.start(CapacityClass::Ordinary, move || async move {
            super::delivery_setup::issue_encrypted(&state.db_pool, &initialized, Some(encryption)).await
        })?.result().await??;
        // Provisioning registered a client after the issuing runtime captured
        // its configuration. Restart explicitly after that configuration change;
        // a stale runtime is not allowed to send.
        dispatcher.deployment().close().await;
        crate::organizations::lifecycle::close_pool(&runtime.state.db_pool).await;
        drop(runtime);
        let (runtime, dispatcher) = Prepared::from_environment().await?.build().await?;
        let before: (i64, Vec<u8>) = sqlx::query_as(
            "SELECT delivery_revision,capability_hash FROM aegaeon.organization_invitations WHERE id=$1",
        ).bind(invitation).fetch_one(&admin).await?;
        let transport = if lose_reply {
            TransportFixture::lose_first_reply()?
        } else {
            TransportFixture::new(204, vec![], Duration::ZERO, false)?
        };
        let expected = if lose_reply { 2 } else { 1 };
        let started = std::time::Instant::now();
        let received = transport.received.clone();
        let worker_keys = WorkerConfiguration::load(&key_path)?;
        super::super::notification_worker::run(runtime, dispatcher, worker_keys, trust, once, async move {
            if once { std::future::pending::<()>().await; }
            // Bounded explicit shutdown; run() finishes any current attempt first.
            // Keep the actual persisted 60..120-second retry delay; no clock,
            // SQL due-time or scheduling substitution is used in this case.
            let polls = if lose_reply { 1500 } else { 100 };
            for _ in 0..polls {
                if received.lock().unwrap().len() >= expected { break; }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await?;
        let observed = transport.received.lock().unwrap();
        anyhow::ensure!(observed.len() == expected);
        anyhow::ensure!(observed[0]["version"] == 2);
        anyhow::ensure!(observed[0]["environmentId"] == environment.to_string());
        anyhow::ensure!(observed[0]["domainId"] == domain.to_string());
        anyhow::ensure!(observed[0]["invitationId"] == invitation.to_string());
        anyhow::ensure!(observed[0]["recipient"] == "Invitee@example.test");
        anyhow::ensure!(observed[0]["fixtureMessageId"] == observed[0]["messageId"]);
        let capability = Zeroizing::new(observed[0]["capability"].as_str().ok_or_else(|| anyhow::anyhow!("missing delivery proof"))?.to_owned());
        if lose_reply {
            anyhow::ensure!(observed[0] == observed[1]);
            anyhow::ensure!(started.elapsed() >= Duration::from_secs(60));
        }
        drop(observed);
        let stored: (String, String, bool, i16) = sqlx::query_as(
            "SELECT state,last_outcome,encrypted_payload IS NULL,attempts FROM aegaeon.notification_messages WHERE object_id=$1",
        ).bind(invitation).fetch_one(&admin).await?;
        anyhow::ensure!(stored == ("terminal".into(), "accepted".into(), true, if lose_reply { 2 } else { 1 }));
        let active: i32 = sqlx::query_scalar("SELECT active_messages FROM aegaeon.notification_queue_capacity WHERE environment_id=$1")
            .bind(environment).fetch_one(&admin).await?;
        anyhow::ensure!(active == 0);
        let after: (i64, Vec<u8>) = sqlx::query_as(
            "SELECT delivery_revision,capability_hash FROM aegaeon.organization_invitations WHERE id=$1",
        ).bind(invitation).fetch_one(&admin).await?;
        anyhow::ensure!(before == after);
        if lose_reply {
            verify_delivered_proof(environment, domain, invitation, capability).await?;
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    pool.close().await;
    admin.close().await;
    result
}

#[test]
#[ignore = "requires owned current PostgreSQL TLS supplier and restricted runtime grants"]
fn notification_current_worker_once_delivers_and_releases() -> Result<()> {
    with_environment(tokio::runtime::Builder::new_current_thread(), || {
        exercise(true, false)
    })
}

#[test]
#[ignore = "requires owned current PostgreSQL TLS supplier and restricted runtime grants"]
fn notification_current_worker_continuous_drains_current_attempt() -> Result<()> {
    with_environment(tokio::runtime::Builder::new_current_thread(), || {
        exercise(false, false)
    })
}

/// Use the delivered invitation capability through the real purpose handler.
/// Roll back the new child request so this test creates no additional mail.
async fn verify_delivered_proof(
    environment: Uuid,
    domain: Uuid,
    invitation: Uuid,
    capability: Zeroizing<String>,
) -> Result<()> {
    use crate::organizations::{invitations::enrollment, Scope};
    let (runtime, dispatcher) = Prepared::from_environment().await?.build().await?;
    let pool = runtime.state.db_pool.clone();
    let result = dispatcher
        .start(CapacityClass::Ordinary, move || async move {
            let mut tx = pool.begin().await?;
            let input = enrollment::Request {
                request_id: "lost-reply-proof-use",
                scope: Scope {
                    environment_id: environment,
                    domain_id: domain,
                },
                invitation,
                capability: &capability,
                purpose: enrollment::Purpose::Registration,
                login_identifier: None,
                key: "lost-reply-proof-use",
                now: i64::try_from(crate::util::now_unix_epoch_secs()?)?,
            };
            enrollment::request(&mut tx, &input, None).await?;
            tx.rollback().await?;
            // The same delivered proof must stop working when current policy closes.
            let mut tx = pool.begin().await?;
            sqlx::query(
                "UPDATE aegaeon.environments SET organization_identity_policy=NULL WHERE id=$1",
            )
            .bind(environment)
            .execute(&mut *tx)
            .await?;
            anyhow::ensure!(enrollment::request(&mut tx, &input, None).await.is_err());
            tx.rollback().await?;
            Ok::<_, anyhow::Error>(())
        })?
        .result()
        .await;
    dispatcher.deployment().close().await;
    crate::organizations::lifecycle::close_pool(&runtime.state.db_pool).await;
    result??;
    Ok(())
}

#[test]
#[ignore = "requires owned current PostgreSQL TLS supplier and actual retry deadline"]
fn notification_current_worker_lost_reply_retries_same_usable_proof() -> Result<()> {
    with_environment(tokio::runtime::Builder::new_current_thread(), || {
        exercise(false, true)
    })
}
