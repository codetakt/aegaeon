//! Configured runtime worker + real owned TLS envelopes + actual recipient API.
use super::*;
use crate::organizations::invitations::transport::{
    fixture::Fixture as TransportFixture, Credential,
};
use crate::organizations::operators::mutations::delivery::{self as config, Change, Channel};
use crate::web::OrganizationDeliveryRequest;
use std::time::Duration;

pub(super) fn credential() -> String {
    URL_SAFE_NO_PAD.encode([37u8; 32])
}
pub(super) async fn configure(f: &RecipientFixture) -> TestResult {
    let mut tx = f.base.pool.begin().await?;
    let revision: i64 =
        sqlx::query_scalar("SELECT revision FROM aegaeon.authorization_domains WHERE id=$1")
            .bind(f.organization.scope.domain_id)
            .fetch_one(&mut *tx)
            .await?;
    config::apply(
        &mut tx,
        f.organization.scope,
        f.base.env.team_id,
        &f.base.actor,
        "delivery",
        &Change {
            expected_revision: revision,
            channel: Some(Channel {
                endpoint: "https://delivery.example.test/envelopes".into(),
                credential_sha256: Credential::parse(credential())
                    .map_err(|()| "credential")?
                    .digest(),
            }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
fn request(f: &RecipientFixture, challenge: Option<Uuid>) -> OrganizationDeliveryRequest {
    OrganizationDeliveryRequest {
        identity_request_id: None,
        domain_id: f.organization.scope.domain_id,
        invitation_id: f.invitation,
        challenge_id: challenge,
        credential: credential(),
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn shared_redis_organizations_delivery_tls_to_actual_recipient_acceptance() -> TestResult {
    let mut f = setup::undelivered().await?;
    let result = async {
        configure(&f).await?;
        let transport = TransportFixture::new(204, vec![], Duration::ZERO, false)?;
        let first = f
            .state
            .deliver_organization_invitation(request(&f, None))
            .await?;
        assert_eq!(first.outcome, "acknowledged");
        assert_eq!(
            f.state
                .deliver_organization_invitation(request(&f, None))
                .await?
                .outcome,
            "idle"
        );
        let envelope = transport.received.lock().unwrap()[0].clone();
        assert_eq!(envelope["template"], "organization_invitation");
        assert_eq!(envelope["recipient"], "Invitee@example.test");
        assert_eq!(envelope["fixtureAuthorizationPresent"], true);
        f.capability = envelope["capability"].as_str().ok_or("secret")?.into();
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (_, token) = f.token(&key).await?;
        let token = token.as_str();
        let path = f.path("challenges");
        let proof = f.proof(&key, token, &path)?;
        let (status, value) = f
            .post(
                &path,
                token,
                Some(&proof),
                &json!({"invitationCapability":f.capability}),
            )
            .await?;
        assert_eq!(status, StatusCode::OK);
        let challenge = Uuid::parse_str(value["challengeId"].as_str().ok_or("challenge")?)?;
        assert_eq!(
            f.state
                .deliver_organization_invitation(request(&f, Some(challenge)))
                .await?
                .outcome,
            "acknowledged"
        );
        let confirmation = transport.received.lock().unwrap()[1].clone();
        assert_eq!(confirmation["template"], "organization_recipient_challenge");
        assert_eq!(confirmation["invitationId"], f.invitation.to_string());
        let path = f.path("accept");
        let proof = f.proof(&key, token, &path)?;
        let (status, value) = f
            .post(
                &path,
                token,
                Some(&proof),
                &json!({"invitationCapability":f.capability,
            "challengeId":challenge,"challengeCapability":confirmation["capability"]}),
            )
            .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["organizationId"], f.organization.id.to_string());
        let audit: Vec<String> = sqlx::query_scalar(
            "SELECT data::text FROM aegaeon.organization_authority_events WHERE organization_id=$1",
        )
        .bind(f.organization.id)
        .fetch_all(&f.base.pool)
        .await?;
        for data in audit {
            assert!(!data.contains(&f.capability));
            assert!(!data.contains(confirmation["capability"].as_str().ok_or("secret")?));
            assert!(!data.contains("Invitee@example.test"));
        }
        assert_eq!(transport.received.lock().unwrap().len(), 2);
        drop(transport);
        Ok(())
    }
    .await;
    fixture::finish(&f.state).await?;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn shared_redis_organizations_delivery_tls_refusals_remain_non_authorizing() -> TestResult {
    for (status, body, delay, wrong_name, expected) in [
        (302, vec![], Duration::ZERO, false, "uncertain"),
        (500, vec![], Duration::ZERO, false, "uncertain"),
        (400, vec![], Duration::ZERO, false, "rejected"),
        (200, vec![b'x'; 1025], Duration::ZERO, false, "uncertain"),
        (204, vec![], Duration::ZERO, true, "uncertain"),
        (204, vec![], Duration::from_secs(11), false, "uncertain"),
    ] {
        let f = setup::undelivered().await?;
        let result = async {
            configure(&f).await?;
            let transport = TransportFixture::new(status, body, delay, wrong_name)?;
            assert_eq!(
                f.state
                    .deliver_organization_invitation(request(&f, None))
                    .await?
                    .outcome,
                expected
            );
            assert_eq!(
                f.state
                    .deliver_organization_invitation(request(&f, None))
                    .await?
                    .outcome,
                "idle"
            );
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1",
            )
            .bind(f.organization.id)
            .fetch_one(&f.base.pool)
            .await?;
            assert_eq!(count, 0);
            assert_eq!(
                transport.received.lock().unwrap().len(),
                usize::from(!wrong_name)
            );
            drop(transport);
            Ok(())
        }
        .await;
        fixture::finish(&f.state).await?;
        f.base.cleanup(result).await?;
    }
    Ok(())
}
