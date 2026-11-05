//! Enabled-policy production construction and delivery; only TLS trust/DNS is injected.
use super::*;
use super::{delivery_setup, fixture::Context};
use crate::organizations::invitations::transport::fixture::Fixture as TransportFixture;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{io::Write, os::unix::fs::OpenOptionsExt};

#[test]
#[ignore = "requires owned independent TLS PostgreSQL clusters, v8 catalog and TLS Redis"]
fn organization_production_delivery_from_enabled_policy_sends_once_and_fences() -> Result<()> {
    with_environment(tokio::runtime::Builder::new_current_thread(), || async {
        let Context {
            prepared,
            mut control,
            deployment,
            scope,
            initialized,
            issuer,
            configuration,
        } = super::fixture::prepare(true).await?;
        let path = PathBuf::from(std::env::var("AEGAEON_TEST_ORGANIZATION_STARTUP_FIXTURE")?)
            .with_file_name("runtime.json");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&configuration)?;
        drop(file);
        let _config = EnvVarGuard::new(
            "AEGAEON_ORGANIZATION_RUNTIME_CONFIG",
            Some(
                path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("fixture path"))?,
            ),
        );
        let _issuer = EnvVarGuard::new(
            "AEGAEON_RUNTIME_ISSUER_HOST",
            Some(&initialized.issuer_host),
        );
        let pool = prepared.startup.pool.clone();
        let result = async {
            let (runtime, dispatcher) = super::fixture::build_for_fixture(prepared).await?;
            anyhow::ensure!(runtime
                .state
                .cfg
                .authorization_details_types_supported
                .iter()
                .any(|t| t == crate::organizations::ORGANIZATION_ACCESS_TYPE));
            let state = runtime.state.clone();
            let (domain, invitation) = dispatcher
                .start(CapacityClass::Ordinary, move || async move {
                    delivery_setup::issue(&state.db_pool, &initialized).await
                })?
                .result()
                .await??;
            // Current-thread Tokio keeps the test-only TLS trust/DNS binding on this thread.
            let transport = TransportFixture::new(204, vec![], Duration::ZERO, false)?;
            let request = |credential| OrganizationDeliveryRequest {
                domain_id: domain,
                invitation_id: invitation,
                challenge_id: None,
                identity_request_id: None,
                credential,
            };
            let rejected =
                deliver_organization_invitation(request(URL_SAFE_NO_PAD.encode([38u8; 32]))).await;
            anyhow::ensure!(rejected.is_err());
            anyhow::ensure!(transport.received.lock().unwrap().is_empty());
            let delivered =
                deliver_organization_invitation(request(delivery_setup::credential())).await?;
            anyhow::ensure!(delivered.outcome == "acknowledged");
            let repeated =
                deliver_organization_invitation(request(delivery_setup::credential())).await?;
            anyhow::ensure!(repeated.outcome == "idle");
            {
                let messages = transport.received.lock().unwrap();
                anyhow::ensure!(messages.len() == 1);
                let envelope = &messages[0];
                anyhow::ensure!(envelope["template"] == "organization_invitation");
                anyhow::ensure!(envelope["recipient"] == "Invitee@example.test");
                anyhow::ensure!(envelope["environmentId"] == scope.environment_id.to_string());
                anyhow::ensure!(envelope["domainId"] == domain.to_string());
                anyhow::ensure!(envelope["invitationId"] == invitation.to_string());
                anyhow::ensure!(envelope["issuer"] == issuer);
                anyhow::ensure!(envelope["fixtureAuthorizationPresent"] == true);
                anyhow::ensure!(envelope["capability"]
                    .as_str()
                    .is_some_and(|v| !v.is_empty()));
            }
            anyhow::ensure!(control.pending(deployment).await?.state.pending == 0);
            anyhow::ensure!(
                control
                    .environment_maintenance()?
                    .pending(scope)
                    .await?
                    .state
                    .pending
                    == 0
            );
            control.fence(deployment, Uuid::new_v4(), 3).await?;
            anyhow::ensure!(
                deliver_organization_invitation(request(delivery_setup::credential()))
                    .await
                    .is_err()
            );
            anyhow::ensure!(transport.received.lock().unwrap().len() == 1);
            Ok::<_, anyhow::Error>(())
        }
        .await;
        tokio::time::timeout(Duration::from_secs(10), pool.close()).await?;
        control.close().await?;
        result
    })
}
