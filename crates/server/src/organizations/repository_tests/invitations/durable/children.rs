use super::*;
use crate::organizations::invitations::{
    durable::{reissue, Reissue},
    enrollment,
};

async fn accept_message(
    f: &InvitationFixture,
    selection: Selection,
    ring: &PrivateKeyRing,
    at: i64,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let scope = f.base.organization.scope;
    let mut tx = f.base.pool.begin().await?;
    let mut claims = queue::claim(
        &mut tx,
        scope.environment_id,
        selection,
        Uuid::new_v4(),
        1,
        at,
    )
    .await?;
    assert_eq!(claims.len(), 1);
    let claim = claims.remove(0);
    tx.commit().await?;
    let mut tx = f.base.pool.begin().await?;
    let authorized = invite::durable::admit_current(
        &mut tx,
        scope,
        &claim,
        selection,
        &"a".repeat(64),
        at + 1,
        None,
    )
    .await?;
    tx.commit().await?;
    let value = serde_json::from_slice(&authorized.open(ring, at + 2)?)?;
    let mut tx = f.base.pool.begin().await?;
    queue::complete(
        &mut tx,
        &claim,
        CompletedAttempt {
            attempts: 1,
            observed_at: (at + 3) as u64,
            outcome: TransportOutcome::Accepted,
            retry_after: None,
        },
        0,
    )
    .await?;
    tx.commit().await?;
    Ok(value)
}

async fn recovery_target(f: &InvitationFixture) -> TestResult {
    let user = f.base.users[0];
    // Fixture input deliberately has uppercase domain spelling; the verified
    // destination must use the same mailbox contract as invitation issuance.
    let address = invite::recipient_address(&f.request.recipient)?;
    sqlx::query("UPDATE aegaeon.end_users SET email=lower($2) WHERE id=$1")
        .bind(user)
        .bind(&address)
        .execute(&f.base.pool)
        .await?;
    sqlx::query("INSERT INTO aegaeon.end_user_profiles(end_user_id,email_verified,verified_delivery_address) VALUES ($1,false,$2) ON CONFLICT(end_user_id) DO UPDATE SET verified_delivery_address=$2")
        .bind(user).bind(&address).execute(&f.base.pool).await?;
    let hash = crate::local_credentials::hash_password("Fixture-Recovery-Password-7!")?;
    sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash,status) VALUES ($1,$2,'ACTIVE')")
        .bind(user).bind(hash).execute(&f.base.pool).await?;
    Ok(())
}

async fn exercise(kind: u8) -> TestResult {
    let current = CurrentFixture::new().await?;
    let f = &current.fixture;
    let result = current.run(async {
        let (ring, selection) = configure(f).await?;
        let scope = f.base.organization.scope;
        sqlx::query("UPDATE aegaeon.environments SET organization_identity_policy=$2 WHERE id=$1")
            .bind(scope.environment_id)
            .bind(serde_json::json!({"registration":true,"passwordRecovery":true,"subjectFormat":"uuid"}))
            .execute(&f.base.pool).await?;
        if kind == 2 { recovery_target(f).await?; }
        let mut tx = f.base.pool.begin().await?;
        let invitation = invite::issue_first_admin(&mut tx, f.issuance()).await?;
        tx.commit().await?;
        let invitation_mail = accept_message(f, selection, &ring, 100).await?;
        let capability = invitation_mail["capability"].as_str().ok_or("invitation proof")?;
        let mut tx = f.base.pool.begin().await?;
        let child = if kind == 0 {
            let mut input = f.acceptance(invitation.id, capability, Uuid::nil(), "");
            input.now = 105;
            invite::request_challenge(&mut tx, &input, "durable-child").await?
        } else {
            enrollment::request(&mut tx, &enrollment::Request {
                request_id:"durable-child", scope, invitation:invitation.id, capability,
                purpose: if kind == 1 { enrollment::Purpose::Registration } else { enrollment::Purpose::PasswordRecovery },
                login_identifier: (kind == 2).then_some(f.request.recipient.as_str()),
                key:"durable-child", now:105,
            }, None).await?
        };
        tx.commit().await?;
        if kind == 2 {
            let target: Option<Uuid> = sqlx::query_scalar("SELECT target_user_id FROM aegaeon.organization_identity_requests WHERE id=$1")
                .bind(child).fetch_one(&f.base.pool).await?;
            assert_eq!(target, Some(f.base.users[0]));
        }
        let old_mail = accept_message(f, selection, &ring, 106).await?;
        let expected = ["organization_recipient_challenge", "organization_identity_registration", "organization_identity_recovery"][usize::from(kind)];
        assert_eq!(old_mail["template"], expected);
        assert_eq!(old_mail["objectId"], child.to_string());
        assert_eq!(old_mail["invitationId"], invitation.id.to_string());
        let command = Reissue { scope, invitation:invitation.id,
            challenge:(kind==0).then_some(child), identity_request:(kind!=0).then_some(child),
            expected_delivery_revision:1, operation:Uuid::new_v4() };
        let mut tx = f.base.pool.begin().await?;
        let replacement = reissue(&mut tx, &command, &"a".repeat(64), 166, None).await?;
        tx.commit().await?;
        let new_mail = accept_message(f, selection, &ring, 167).await?;
        assert_eq!(new_mail["messageId"], replacement.message_id.to_string());
        assert_ne!(new_mail["messageId"], old_mail["messageId"]);
        assert_ne!(new_mail["capability"], old_mail["capability"]);
        assert_eq!(new_mail["expiresAt"], old_mail["expiresAt"]);
        assert_eq!(new_mail["recipient"], old_mail["recipient"]);
        for (mail, accepted) in [(&old_mail, false), (&new_mail, true)] {
            let proof = mail["capability"].as_str().ok_or("child proof")?;
            let mut tx = f.base.pool.begin().await?;
            let valid = if kind == 0 {
                let mut input = f.acceptance(invitation.id, capability, child, proof);
                input.now = 171;
                invite::accept_first_admin(&mut tx, &input).await.is_ok()
            } else {
                enrollment::prepare_completion(&mut tx, &enrollment::Completion {
                    request_id:"child-proof-check",scope,invitation:invitation.id,request:child,proof,now:171,
                }, None).await.is_ok()
            };
            assert_eq!(valid, accepted);
            tx.rollback().await?;
        }
        // Purpose revocation prevents a new explicit reissue as well as new mail admission.
        let mut tx = f.base.pool.begin().await?;
        invite::revoke(&mut tx, invite::Revocation { scope, team:f.base.env.team_id,
            actor:&f.base.actor,key:"revoke-child-parent",id:invitation.id,expected_revision:1 }).await?;
        tx.commit().await?;
        let mut tx = f.base.pool.begin().await?;
        assert!(reissue(&mut tx, &Reissue { expected_delivery_revision:2, operation:Uuid::new_v4(), ..command }, &"a".repeat(64), 227, None).await.is_err());
        tx.rollback().await?;
        Ok(())
    }).await;
    current.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated current PostgreSQL and explicit Redis observation supplier"]
async fn pg_organizations_durable_challenge_reissue_preserves_current_acceptance() -> TestResult {
    exercise(0).await
}

#[tokio::test]
#[ignore = "requires isolated current PostgreSQL and explicit Redis observation supplier"]
async fn pg_organizations_durable_registration_reissue_preserves_current_proof() -> TestResult {
    exercise(1).await
}

#[tokio::test]
#[ignore = "requires isolated current PostgreSQL and explicit Redis observation supplier"]
async fn pg_organizations_durable_recovery_reissue_preserves_current_proof() -> TestResult {
    exercise(2).await
}
