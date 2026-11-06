//! Real production construction with separate TLS suppliers and restricted roles.
//! Fixture provisioning is explicit; it does not qualify production nonrollback custody.
use super::*;
use crate::organizations::{
    store_observation::{Postgres, Redis},
    witness::{
        deployment::{DeploymentControl, DeploymentId},
        Role, Scope, Selection,
    },
};
use crate::web::management::initialization::{
    initialize_management, InitializationInput, InitializationOutput,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::{postgres::PgConnectOptions, Connection};
use std::{path::PathBuf, str::FromStr};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    control: String,
    maintenance: String,
    primary: String,
    primary_maintenance: String,
    token: String,
    ca: PathBuf,
}

fn selection_json(value: &Selection) -> serde_json::Value {
    json!({"epoch":value.epoch,"primary":value.primary,"token_store":value.token_store,
        "source_sha256":value.source_sha256,"history_sha256":value.history_sha256,
        "acceptance_sha256":value.acceptance_sha256})
}

pub(super) struct Context {
    pub prepared: Prepared,
    pub control: DeploymentControl,
    pub deployment: DeploymentId,
    pub scope: Scope,
    pub initialized: InitializationOutput,
    pub issuer: String,
    pub configuration: Vec<u8>,
}

// Initial fixture construction preserves the inner error for diagnosis. Delivery
// itself always uses the public entry, including its production error redaction.
pub(super) async fn build_for_fixture(
    prepared: Prepared,
) -> Result<(BuiltServerRuntime, EnvironmentDispatcher)> {
    let Prepared {
        issuer_host,
        bootstrap,
        startup,
        dispatcher,
        ..
    } = prepared;
    let runtime = dispatcher
        .start(CapacityClass::Ordinary, move || async move {
            build_server_runtime_with_inputs(issuer_host, bootstrap, Some(startup)).await
        })?
        .result()
        .await??;
    Ok((runtime, dispatcher))
}

pub(super) async fn prepare(enabled: bool) -> anyhow::Result<Context> {
    // Keep component failures in the private fixture capture. Ordinary production
    // error responses remain redacted; this never exports fixture store credentials.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    crate::install_rustls_crypto_provider();
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(std::env::var(
        "AEGAEON_TEST_ORGANIZATION_STARTUP_FIXTURE",
    )?)?)?;
    let options = PgConnectOptions::from_str(&fixture.primary)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(&fixture.ca);
    let bootstrap_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.clone())
        .await?;
    let initialized = initialize_management(
        &bootstrap_pool,
        &InitializationInput {
            owner_email: "owner@example.test".into(),
            owner_password: "Independent-Fixture-Password-7!".into(),
            allowed_origins: vec!["https://admin.example.test".into()],
            issuer_base_domain: "example.test".into(),
        },
    )
    .await;
    let initialized = initialized?;
    if enabled {
        super::delivery_setup::enable_policy(&bootstrap_pool, &initialized).await?;
    }
    bootstrap_pool.close().await;
    let issuer = format!("https://{}", initialized.issuer_host);
    let deployment = DeploymentId::new(Uuid::new_v4())?;
    let selection = Selection {
        epoch: Uuid::new_v4(),
        primary: Uuid::new_v4(),
        token_store: Uuid::new_v4(),
        source_sha256: "1".repeat(64),
        history_sha256: "2".repeat(64),
        acceptance_sha256: "3".repeat(64),
    };
    let mut child = Selection {
        epoch: Uuid::new_v4(),
        ..selection.clone()
    };
    let scope = Scope {
        environment_id: initialized.environment_id,
        deployment_id: deployment.uuid(),
    };
    let mut control =
        DeploymentControl::connect(&fixture.maintenance, &fixture.ca, Role::Maintenance).await?;
    // Drained initial seal pinning uses separately provisioned maintenance
    // authority. The generated runtime configuration retains its runtime login.
    let maintenance_options = PgConnectOptions::from_str(&fixture.primary_maintenance)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(&fixture.ca);
    let mut primary =
        Postgres::observe(sqlx::PgConnection::connect_with(&maintenance_options).await?).await?;
    let redis = redis::Client::build_with_tls(
        fixture.token.as_str(),
        redis::TlsCertificates {
            client_tls: None,
            root_cert: Some(std::fs::read(&fixture.ca)?),
        },
    )?;
    let mut token = Redis::observe(redis.get_multiplexed_async_connection().await?).await?;
    let operation = Uuid::new_v4();
    control.initialize(deployment, operation).await?;
    let child_operation = Uuid::new_v4();
    control
        .environment_maintenance()?
        .initialize(scope, child_operation)
        .await?;
    if std::env::var_os("AEGAEON_TEST_ORGANIZATION_ENROLLMENT_FIXTURE").is_some() {
        child.history_sha256 =
            history::enroll_empty(&mut control, scope, child_operation, &initialized).await?;
    }
    control
        .prepare(deployment, operation, 1, &selection)
        .await?;
    control
        .pin_store_progress(deployment, operation, 2, &mut primary, &mut token)
        .await?;
    control
        .activate(deployment, operation, 2, &selection.acceptance_sha256)
        .await?;
    let operation = child_operation;
    control
        .environment_maintenance()?
        .prepare(scope, operation, 1, &child)
        .await?;
    control
        .environment_maintenance()?
        .pin_store_progress(scope, operation, 2, &mut primary, &mut token)
        .await?;
    control
        .bind_child(
            deployment,
            selection.epoch,
            initialized.environment_id,
            child.epoch,
        )
        .await?;
    control
        .environment_maintenance()?
        .activate(scope, operation, 2, &child.acceptance_sha256)
        .await?;
    primary.close().await?;
    token.close();
    let bytes = serde_json::to_vec(&json!({
        "version":1,"deployment_id":deployment.uuid(),"selection":selection_json(&selection),
        "control":{"url":fixture.control,"root_cert":fixture.ca},
        "primary":{"url":fixture.primary,"root_cert":fixture.ca},
        "token":{"url":fixture.token,"root_cert":fixture.ca},
        "environments":[{"id":initialized.environment_id,"issuer":issuer,"selection":selection_json(&child)}],
    }))?;
    let prepared = Prepared::new(
        Configuration::parse(&bytes)?,
        initialized.issuer_host.clone(),
        BootstrapConfig::try_from_env()?,
        fixture.token,
    )?;
    Ok(Context {
        prepared,
        control,
        deployment,
        scope,
        initialized,
        issuer,
        configuration: bytes,
    })
}

#[path = "fixture/multiple.rs"]
mod multiple;
pub(super) use multiple::add_environment;

#[path = "fixture/history.rs"]
mod history;
