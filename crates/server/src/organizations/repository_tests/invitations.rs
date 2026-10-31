use super::*;
mod delivery;
mod history_import;
mod recovery;
use crate::organizations::invitations::{
    self as invite, Acceptance, FirstAdminRequest, Issuance, Recipient,
};

struct InvitationFixture {
    base: Fixture,
    request: FirstAdminRequest,
    recipient: Recipient,
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_invitation_finite_delivery_challenges_and_terminal_cancellation(
) -> TestResult {
    let f = InvitationFixture::new().await?;
    let result = f.base.in_epoch(async {
        let (id,secret,challenge,proof) = f.prepared().await?;
        let input = f.acceptance(id,&secret,challenge,&proof);
        let mut tx = f.base.pool.begin().await?;
        let original = invite::issue_first_admin(&mut tx,f.issuance()).await?;
        assert_eq!(original.id,id);
        for index in 1..5 {
            invite::request_challenge(&mut tx,&input,&format!("extra-{index}")).await?;
        }
        assert!(matches!(invite::request_challenge(&mut tx,&input,"exhausted").await,
            Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        tx.commit().await?;
        for now in [161,221,281,341] {
            let mut tx = f.base.pool.begin().await?;
            invite::claim_invitation_delivery(&mut tx,input.scope,id,now).await?;
            tx.commit().await?;
        }
        let mut tx = f.base.pool.begin().await?;
        assert!(matches!(invite::claim_invitation_delivery(&mut tx,input.scope,id,401).await,
            Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        tx.rollback().await?;
        for _ in 0..2 {
            let mut tx = f.base.pool.begin().await?;
            let cancelled = invite::revoke(&mut tx,invite::Revocation { scope:input.scope,team:f.base.env.team_id,
                actor:&f.base.actor,key:"cancel-once",id,expected_revision:6 }).await?;
            assert_eq!(cancelled.state,invite::State::Revoked);
            tx.commit().await?;
        }
        let mut tx = f.base.pool.begin().await?;
        assert!(invite::accept_first_admin(&mut tx,&input).await.is_err());
        tx.rollback().await?;
        let events:i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.invitation_revoked'")
            .bind(f.request.organization_id).fetch_one(&f.base.pool).await?;
        assert_eq!(events,1);


        Ok(())
    }).await;
    f.base.cleanup(result).await
}

impl InvitationFixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let base = Fixture::new().await?;
        operators::principal(&base).await?;
        operators::grant(&base, serde_json::json!(["provision"])).await?;
        let organization = Organization {
            id: Uuid::new_v4(),
            external_id: "first-admin-target".into(),
            state: OrganizationState::Provisioning,
            revision: 1,
            grant_generation: 1,
            scope: base.organization.scope,
        };
        let mut tx = base.pool.begin().await?;
        repository::create_organization(&mut tx, &organization, &base.actor).await?;
        tx.commit().await?;
        let request = FirstAdminRequest {
            organization_id: organization.id,
            expected_revision: 1,
            recipient: "Invitee+Test@EXAMPLE.test".into(),
            roles: BTreeSet::from(["admin".into()]),
            lifetime_seconds: None,
        };
        let recipient = Recipient {
            identity_revision: 1,
            auth_time: 100,
            binding: Binding {
                scope: organization.scope,
                issuer: base.env.issuer_url.clone(),
                client_id: "invitee-client".into(),
                client_registration_id: Uuid::new_v4(),
                subject: format!("organization-user-{}", base.users[1]),
                user_id: base.users[1],
                root_id: "recipient-root".into(),
                dpop_jkt: "recipient-key".into(),
            },
            expires_at: 1000,
        };
        Ok(Self {
            base,
            request,
            recipient,
        })
    }

    fn issuance(&self) -> Issuance<'_> {
        Issuance {
            scope: self.base.organization.scope,
            team: self.base.env.team_id,
            actor: &self.base.actor,
            key: "issue-once",
            request: &self.request,
            now: 100,
        }
    }

    async fn prepared(&self) -> Result<(Uuid, String, Uuid, String), Box<dyn std::error::Error>> {
        let mut tx = self.base.pool.begin().await?;
        let invitation = invite::issue_first_admin(&mut tx, self.issuance()).await?;
        tx.commit().await?;
        let mut tx = self.base.pool.begin().await?;
        let delivery = invite::claim_invitation_delivery(
            &mut tx,
            self.base.organization.scope,
            invitation.id,
            101,
        )
        .await?;
        tx.commit().await?;
        assert_eq!(delivery.recipient, "Invitee+Test@example.test");
        let secret = delivery.capability.into_delivery();
        let mut tx = self.base.pool.begin().await?;
        let mut input = self.acceptance(invitation.id, &secret, Uuid::nil(), "");
        input.now = 102;
        let challenge = invite::request_challenge(&mut tx, &input, "challenge-once").await?;
        assert_eq!(
            invite::request_challenge(&mut tx, &input, "challenge-once").await?,
            challenge
        );
        tx.commit().await?;
        let mut tx = self.base.pool.begin().await?;
        input.challenge_id = challenge;
        let delivery =
            invite::claim_challenge_delivery(&mut tx, input.scope, invitation.id, challenge, 103)
                .await?;
        tx.commit().await?;
        assert_eq!(delivery.recipient, "Invitee+Test@example.test");
        Ok((
            invitation.id,
            secret,
            challenge,
            delivery.capability.into_delivery(),
        ))
    }

    fn acceptance<'a>(
        &'a self,
        id: Uuid,
        secret: &'a str,
        challenge: Uuid,
        proof: &'a str,
    ) -> Acceptance<'a> {
        Acceptance {
            request_id: "recipient-fixture-request",
            scope: self.base.organization.scope,
            invitation_id: id,
            invitation_capability: secret,
            challenge_id: challenge,
            challenge_capability: proof,
            recipient: &self.recipient,
            now: 104,
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_invitation_first_admin_acceptance_and_concurrent_replay_are_atomic(
) -> TestResult {
    let f = InvitationFixture::new().await?;
    let result = f.base.in_epoch(async {
        let (id,secret,challenge,proof) = f.prepared().await?;
        let input = f.acceptance(id,&secret,challenge,&proof);
        let before_revision:i64 = sqlx::query_scalar("SELECT revision FROM aegaeon.organization_invitations WHERE id=$1").bind(id).fetch_one(&f.base.pool).await?;
        let mut first = f.base.pool.begin().await?;
        let member = invite::accept_first_admin(&mut first,&input).await?;
        let mut second = f.base.pool.begin().await?;
        {
        let pending = invite::accept_first_admin(&mut second,&input);
        tokio::pin!(pending);
        assert!(tokio::time::timeout(std::time::Duration::from_millis(50),&mut pending).await.is_err());
        first.commit().await?;
        assert_eq!(pending.await?, member);
        }
        second.commit().await?;
        let mut tx = f.base.pool.begin().await?;
        let org = repository::lock_organization(&mut tx,input.scope,f.request.organization_id).await?;
        assert_eq!((org.state,org.grant_generation),(OrganizationState::Active,2));
        assert_eq!(member.roles, BTreeSet::from(["admin".into()]));
        let count:i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1")
            .bind(org.id).fetch_one(&mut *tx).await?;
        assert_eq!(count,1);
        let events:i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.invitation_accepted'")
            .bind(org.id).fetch_one(&mut *tx).await?;
        assert_eq!(events,1);
        let row = sqlx::query("SELECT actor_id,actor_kind,request_id,client_registration_id,data FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.invitation_accepted'")
            .bind(org.id).fetch_one(&mut *tx).await?;
        use sqlx::Row;
        assert_eq!(row.try_get::<Uuid,_>("actor_id")?,f.recipient.binding.user_id);
        assert_eq!(row.try_get::<String,_>("request_id")?,"recipient-fixture-request");
        assert_eq!(row.try_get::<Uuid,_>("client_registration_id")?,f.recipient.binding.client_registration_id);
        let data: serde_json::Value = row.try_get("data")?;
        assert_eq!(data["authorityBasis"]["kind"],"invitation_recipient");
        assert_eq!(data["authorityBasis"]["inviterId"],f.base.actor.id.to_string());
        assert_eq!(data["before"]["revision"],before_revision);
        assert_eq!(data["after"]["revision"],before_revision + 1);
        let public:String = sqlx::query_scalar("SELECT string_agg(data::text,'') FROM aegaeon.organization_authority_events WHERE organization_id=$1")
            .bind(org.id).fetch_one(&mut *tx).await?;
        for sensitive in [&secret,&proof,&f.request.recipient] { assert!(!public.contains(sensitive)); }
        let retained:String = sqlx::query_scalar("SELECT row_to_json(i)::text FROM aegaeon.organization_invitations i WHERE id=$1")
            .bind(id).fetch_one(&mut *tx).await?;
        assert!(!retained.contains(&secret) && !retained.contains(&proof));
        tx.rollback().await?;
        Ok(())
    }).await;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_invitation_binds_principal_client_root_key_and_delivery_generation(
) -> TestResult {
    let f = InvitationFixture::new().await?;
    let result = f
        .base
        .in_epoch(async {
            let (id, secret, challenge, proof) = f.prepared().await?;
            for field in 0..6 {
                let mut recipient = f.recipient.clone();
                match field {
                    0 => recipient.binding.root_id = "different-root".into(),
                    1 => recipient.binding.dpop_jkt = "different-key".into(),
                    2 => recipient.binding.client_registration_id = Uuid::new_v4(),
                    3 => recipient.binding.client_id = "different-client".into(),
                    4 => {
                        recipient.binding.user_id = f.base.users[0];
                        recipient.binding.subject =
                            format!("organization-user-{}", f.base.users[0]);
                    }
                    _ => recipient.binding.scope.domain_id = Uuid::new_v4(),
                }
                let input = Acceptance {
                    request_id: "recipient-fixture-request",
                    recipient: &recipient,
                    ..f.acceptance(id, &secret, challenge, &proof)
                };
                let mut tx = f.base.pool.begin().await?;
                assert!(
                    invite::accept_first_admin(&mut tx, &input).await.is_err(),
                    "binding field {field}"
                );
                tx.rollback().await?;
            }
            let mut tx = f.base.pool.begin().await?;
            let input = f.acceptance(id, &secret, challenge, &secret);
            assert!(invite::accept_first_admin(&mut tx, &input).await.is_err());
            tx.rollback().await?;
            let mut tx = f.base.pool.begin().await?;
            assert!(
                invite::claim_invitation_delivery(&mut tx, input.scope, id, 120)
                    .await
                    .is_err()
            );
            tx.rollback().await?;
            let mut tx = f.base.pool.begin().await?;
            let delivery = invite::claim_invitation_delivery(&mut tx, input.scope, id, 161).await?;
            tx.commit().await?;
            let new_secret = delivery.capability.into_delivery();
            for invitation_secret in [&secret, &new_secret] {
                let input = Acceptance {
                    request_id: "recipient-fixture-request",
                    now: 162,
                    ..f.acceptance(id, invitation_secret, challenge, &proof)
                };
                let mut tx = f.base.pool.begin().await?;
                assert!(invite::accept_first_admin(&mut tx, &input).await.is_err());
                tx.rollback().await?;
            }
            Ok(())
        })
        .await;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_invitation_rechecks_inviter_roles_expiry_and_global_suspension(
) -> TestResult {
    let f = InvitationFixture::new().await?;
    let result = f.base.in_epoch(async {
        let (id,secret,challenge,proof) = f.prepared().await?;
        let mut input = f.acceptance(id,&secret,challenge,&proof);
        let mut tx = f.base.pool.begin().await?;
        input.now=402; // Challenge issued at102; exclusive expiry402.
        assert!(invite::accept_first_admin(&mut tx,&input).await.is_err());
        tx.rollback().await?;
        input.now=104;
        for mutation in [
            "UPDATE aegaeon.organization_operator_grants SET active=false WHERE domain_id=$1",
            "UPDATE aegaeon.organization_role_definitions SET version=version+1 WHERE domain_id=$1 AND role_key='admin'",
        ] {
            let mut tx = f.base.pool.begin().await?;
            sqlx::query(mutation).bind(input.scope.domain_id).execute(&mut *tx).await?;
            assert!(invite::accept_first_admin(&mut tx,&input).await.is_err());
            tx.rollback().await?;
        }
        let mut tx = f.base.pool.begin().await?;
        sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE id=$1")
            .bind(f.recipient.binding.user_id).execute(&mut *tx).await?;
        assert!(invite::accept_first_admin(&mut tx,&input).await.is_err());
        tx.rollback().await?;
        let mut tx = f.base.pool.begin().await?;
        invite::accept_first_admin(&mut tx,&input).await?;
        tx.commit().await?;
        let mut tx = f.base.pool.begin().await?;
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE domain_id=$1")
            .bind(input.scope.domain_id).execute(&mut *tx).await?;
        assert!(invite::accept_first_admin(&mut tx,&input).await.is_err());
        tx.rollback().await?;
        Ok(())
    }).await;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_invitation_outbox_failure_rolls_back_acceptance_and_recovers(
) -> TestResult {
    let f = InvitationFixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.base.pool).await?;
    let runtime: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&f.base.pool)
        .await?;
    let result = f.base.in_epoch(async {
        let (id,secret,challenge,proof) = f.prepared().await?;
        let input = f.acceptance(id,&secret,challenge,&proof);
        let mut tx = admin.begin().await?;
        sqlx::query("ALTER TABLE aegaeon.organization_authority_outbox ADD CONSTRAINT invitation_fixture_failure CHECK (attempts < 0) NOT VALID").execute(&mut *tx).await?;
        sqlx::query("SELECT set_config('role',$1,true)").bind(&runtime).execute(&mut *tx).await?;
        assert!(matches!(invite::accept_first_admin(&mut tx,&input).await,Err(RepositoryError::Storage(_))));
        tx.rollback().await?;
        let mut tx = f.base.pool.begin().await?;
        let org = repository::lock_organization(&mut tx,input.scope,f.request.organization_id).await?;
        assert_eq!(org.state,OrganizationState::Provisioning);
        assert!(repository::membership(&mut tx,&org,f.recipient.binding.user_id).await?.is_none());
        invite::accept_first_admin(&mut tx,&input).await?;
        tx.commit().await?;
        Ok(())
    }).await;
    admin.close().await;
    f.base.cleanup(result).await
}

mod epochs;
