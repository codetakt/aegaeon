use super::*;
mod children;
mod current;
mod reissue;
use crate::organizations::operators::mutations::delivery::{
    self as configuration, Change, Channel, Encryption,
};
use crate::organizations::{
    lifecycle::Selection,
    notification_envelope::{KeyVersion, PrivateDeliveryKey, PrivateKeyRing, Scope as MailScope},
    notification_outbox as queue,
    notification_retry::{CompletedAttempt, TransportOutcome},
};
// Provider access below creates test-only key material.
#[cfg(test)]
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeySize, PrivateDecryptingKey},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use current::CurrentFixture;
use zeroize::Zeroizing;

async fn configure(
    f: &InvitationFixture,
) -> Result<(PrivateKeyRing, Selection), Box<dyn std::error::Error>> {
    configure_version(f, "delivery_1", 1).await
}

async fn configure_version(
    f: &InvitationFixture,
    key_version: &str,
    expected_revision: i64,
) -> Result<(PrivateKeyRing, Selection), Box<dyn std::error::Error>> {
    let owner = crate::organizations::request_work::async_store::current_epoch_owner(
        f.base.env.environment_id,
    )?;
    let selection = owner.epoch_binding()?.runtime_selection()?;
    let material = PrivateDecryptingKey::generate(KeySize::Rsa2048)?;
    let public = material.public_key().as_der()?;
    let pin = aegaeon_crypto::hash::sha256_digest(public.as_ref());
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"provision\",\"configure\"]'::jsonb WHERE environment_id=$1")
        .bind(f.base.env.environment_id).execute(&f.base.pool).await?;
    let mut tx = f.base.pool.begin().await?;
    configuration::apply(
        &mut tx,
        f.base.organization.scope,
        f.base.env.team_id,
        &f.base.actor,
        &format!("configure-durable-mail-{key_version}-{expected_revision}"),
        &Change {
            expected_revision,
            channel: Some(Channel {
                endpoint: "https://delivery.example.test/envelopes".into(),
                credential_sha256: "a".repeat(64),
                encryption: Some(Encryption {
                    version: key_version.into(),
                    deployment_id: selection.deployment_id(),
                    public_spki: URL_SAFE_NO_PAD.encode(public.as_ref()),
                    spki_sha256: URL_SAFE_NO_PAD.encode(pin),
                    not_before: 0,
                    seal_until: 1_000_000,
                    open_until: 2_000_000,
                }),
            }),
        },
    )
    .await?;
    tx.commit().await?;
    let version = KeyVersion {
        id: key_version.into(),
        deployment_id: selection.deployment_id(),
        scope: MailScope::Domain {
            environment_id: f.base.env.environment_id,
            domain_id: f.base.organization.scope.domain_id,
        },
        not_before: 0,
        seal_until: 1_000_000,
        open_until: 2_000_000,
    };
    let key = PrivateDeliveryKey::new(
        version,
        Zeroizing::new(material.as_der()?.as_ref().to_vec()),
        pin,
    )?;
    Ok((PrivateKeyRing::new(vec![key])?, selection))
}

async fn messages(f: &InvitationFixture) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM aegaeon.notification_messages WHERE environment_id=$1")
        .bind(f.base.env.environment_id)
        .fetch_one(&f.base.pool)
        .await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_organizations_durable_invitation_is_atomic_and_legacy_retry_cannot_rotate() -> TestResult
{
    let current = CurrentFixture::new().await?;
    let f = &current.fixture;
    let result = current.run(async {
        configure(&f).await?;
        let mut tx = f.base.pool.begin().await?;
        let rolled_back = invite::issue_first_admin(&mut tx, f.issuance()).await?;
        let inside: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.notification_messages WHERE object_id=$1")
            .bind(rolled_back.id).fetch_one(&mut *tx).await?;
        assert_eq!(inside, 1);
        tx.rollback().await?;
        assert_eq!(messages(&f).await?, 0);
        let absent: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_invitations WHERE id=$1")
            .bind(rolled_back.id).fetch_one(&f.base.pool).await?;
        assert_eq!(absent, 0);
        let mut tx = f.base.pool.begin().await?;
        let issued = invite::issue_first_admin(&mut tx, f.issuance()).await?;
        tx.commit().await?;
        assert_eq!(issued.revision, 1);
        let initial: (Uuid, String) = sqlx::query_as("SELECT id,encrypted_payload FROM aegaeon.notification_messages WHERE object_id=$1")
            .bind(issued.id).fetch_one(&f.base.pool).await?;
        let mut tx = f.base.pool.begin().await?;
        assert_eq!(invite::issue_first_admin(&mut tx, f.issuance()).await?.id, issued.id);
        tx.commit().await?;
        assert_eq!(messages(&f).await?, 1);
        let mut tx = f.base.pool.begin().await?;
        assert!(invite::claim_invitation_delivery(&mut tx, f.base.organization.scope, issued.id, 161).await.is_err());
        tx.rollback().await?;
        let after: (Uuid, String) = sqlx::query_as("SELECT id,encrypted_payload FROM aegaeon.notification_messages WHERE object_id=$1")
            .bind(issued.id).fetch_one(&f.base.pool).await?;
        assert_eq!(initial, after);
        let proof: (i64, Vec<u8>) = sqlx::query_as("SELECT delivery_revision,capability_hash FROM aegaeon.organization_invitations WHERE id=$1")
            .bind(issued.id).fetch_one(&f.base.pool).await?;
        assert_eq!(proof.0, 1);
        assert_eq!(proof.1.len(), 32);
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.notification_queued'")
            .bind(f.request.organization_id).fetch_one(&f.base.pool).await?;
        assert_eq!(events, 1);
        Ok(())
    }).await;
    current.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_organizations_durable_send_checks_current_authority_before_open() -> TestResult {
    let current = CurrentFixture::new().await?;
    let f = &current.fixture;
    let result = current
        .run(async {
            let (ring, selection) = configure(&f).await?;
            let scope = f.base.organization.scope;
            let mut tx = f.base.pool.begin().await?;
            let invitation = invite::issue_first_admin(&mut tx, f.issuance()).await?;
            tx.commit().await?;
            let mut tx = f.base.pool.begin().await?;
            assert!(queue::claim_delivery(
                &mut tx,
                scope.environment_id,
                selection,
                Uuid::new_v4(),
                queue::ClaimRoute {
                    credential_digest: &"b".repeat(64),
                    ring: &ring
                },
                1,
                100
            )
            .await?
            .is_empty());
            let attempts: i16 = sqlx::query_scalar(
                "SELECT attempts FROM aegaeon.notification_messages WHERE object_id=$1",
            )
            .bind(invitation.id)
            .fetch_one(&mut *tx)
            .await?;
            assert_eq!(attempts, 0);
            let mut claims = queue::claim_delivery(
                &mut tx,
                scope.environment_id,
                selection,
                Uuid::new_v4(),
                queue::ClaimRoute {
                    credential_digest: &"a".repeat(64),
                    ring: &ring,
                },
                1,
                100,
            )
            .await?;
            assert_eq!(claims.len(), 1);
            let claim = claims.remove(0);
            tx.commit().await?;
            let mut tx = f.base.pool.begin().await?;
            assert!(invite::durable::admit_current(
                &mut tx,
                scope,
                &claim,
                selection,
                &"b".repeat(64),
                101,
                None
            )
            .await
            .is_err());
            tx.rollback().await?;
            let mut tx = f.base.pool.begin().await?;
            let authorized = invite::durable::admit_current(
                &mut tx,
                scope,
                &claim,
                selection,
                &"a".repeat(64),
                102,
                None,
            )
            .await?;
            tx.commit().await?;
            assert_eq!(
                authorized.endpoint,
                "https://delivery.example.test/envelopes"
            );
            assert!(authorized.open(&PrivateKeyRing::new(vec![])?, 103).is_err());
            let bytes = authorized.open(&ring, 103)?;
            let payload: serde_json::Value = serde_json::from_slice(&bytes)?;
            assert_eq!(payload["messageId"], claim.message_id.to_string());
            assert_eq!(payload["invitationId"], invitation.id.to_string());
            assert_eq!(payload["recipient"], "Invitee+Test@example.test");
            assert!(authorized.open(&ring, 101).is_err());
            assert!(authorized.open(&ring, claim.lease_until).is_err());
            let mut tx = f.base.pool.begin().await?;
            queue::complete(
                &mut tx,
                &claim,
                CompletedAttempt {
                    attempts: 1,
                    observed_at: 104,
                    outcome: TransportOutcome::Uncertain,
                    retry_after: None,
                },
                0,
            )
            .await?;
            tx.commit().await?;
            let mut tx = f.base.pool.begin().await?;
            let mut claims = queue::claim(
                &mut tx,
                scope.environment_id,
                selection,
                Uuid::new_v4(),
                1,
                164,
            )
            .await?;
            assert_eq!(claims.len(), 1);
            let claim = claims.remove(0);
            tx.commit().await?;
            let mut tx = f.base.pool.begin().await?;
            invite::revoke(
                &mut tx,
                invite::Revocation {
                    scope,
                    team: f.base.env.team_id,
                    actor: &f.base.actor,
                    key: "revoke-before-send",
                    id: invitation.id,
                    expected_revision: 1,
                },
            )
            .await?;
            tx.commit().await?;
            let mut tx = f.base.pool.begin().await?;
            assert!(invite::durable::admit_current(
                &mut tx,
                scope,
                &claim,
                selection,
                &"a".repeat(64),
                165,
                None
            )
            .await
            .is_err());
            tx.rollback().await?;
            Ok(())
        })
        .await;
    current.finish(result).await
}
