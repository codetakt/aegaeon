use super::*;
use crate::organizations::invitation_capabilities as cap;
use crate::organizations::invitations::durable::{reissue, Reissue};

async fn proof_row(f: &InvitationFixture, id: Uuid) -> Result<(i64, Vec<u8>), sqlx::Error> {
    sqlx::query_as("SELECT delivery_revision,capability_hash FROM aegaeon.organization_invitations WHERE id=$1")
        .bind(id).fetch_one(&f.base.pool).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_organizations_notification_reissue_operation_rejects_another_principal() -> TestResult {
    let current = CurrentFixture::new().await?;
    let f = &current.fixture;
    let result = current.run(async {
        configure(f).await?;
        let mut other = f.base.actor.clone();
        other.id = Uuid::new_v4();
        let mut tx = f.base.pool.begin().await?;
        sqlx::query("INSERT INTO aegaeon.administrators(id,email,password_hash,kind,status) VALUES ($1,$2,'synthetic-unused-hash','HUMAN','ACTIVE')")
            .bind(other.id).bind(format!("{}@operator.example",other.id)).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO aegaeon.team_memberships(team_id,administrator_id,role) VALUES ($1,$2,'OWNER')")
            .bind(f.base.env.team_id).bind(other.id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO aegaeon.organization_operator_grants(id,environment_id,domain_id,administrator_id,capabilities,active) VALUES ($1,$2,$3,$4,'[\"provision\"]',true)")
            .bind(Uuid::new_v4()).bind(f.base.organization.scope.environment_id)
            .bind(f.base.organization.scope.domain_id).bind(other.id).execute(&mut *tx).await?;
        let first = invite::issue_first_admin(&mut tx, f.issuance()).await?;
        let second = invite::issue_first_admin(&mut tx, invite::Issuance {
            actor:&other,key:"different-principal",..f.issuance()
        }).await?;
        tx.commit().await?;
        let before = proof_row(f, second.id).await?;
        let command = Reissue {
            scope:f.base.organization.scope,invitation:first.id,challenge:None,
            identity_request:None,expected_delivery_revision:1,operation:Uuid::new_v4(),
        };
        let mut tx = f.base.pool.begin().await?;
        let accepted = reissue(&mut tx,&command,&"a".repeat(64),161,None).await?;
        tx.commit().await?;
        let mut changed = command.clone();
        changed.invitation = second.id;
        let mut tx = f.base.pool.begin().await?;
        assert!(matches!(reissue(&mut tx,&changed,&"a".repeat(64),161,None).await,
            Err(RepositoryError::Authority(AuthorityError::Conflict))));
        tx.rollback().await?;
        assert_eq!(proof_row(f,second.id).await?,before);
        assert_eq!(messages(f).await?,3);
        let events:i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE environment_id=$1 AND event_type='organization.notification_reissued'")
            .bind(command.scope.environment_id).fetch_one(&f.base.pool).await?;
        assert_eq!(events,1);
        // The database constraint is independent of the application lookup and
        // still rejects another principal attempting the same service UUID.
        let mut tx = f.base.pool.begin().await?;
        let collision = sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result) SELECT environment_id,domain_id,$3,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND operation='notification_reissue' AND idempotency_key=$2")
            .bind(command.scope.environment_id).bind(command.operation.to_string()).bind(other.id)
            .execute(&mut *tx).await.unwrap_err();
        assert_eq!(collision.as_database_error().and_then(|e| e.code()).as_deref(),Some("23505"));
        tx.rollback().await?;
        let mut tx = f.base.pool.begin().await?;
        assert!(reissue(&mut tx,&command,&"a".repeat(64),162,None).await? == accepted);
        tx.commit().await?;
        // A distinct operation remains usable; collision refusal did not consume
        // the other object's proof or permanently reserve its future operations.
        changed.operation = Uuid::new_v4();
        let mut tx = f.base.pool.begin().await?;
        assert_eq!(reissue(&mut tx,&changed,&"a".repeat(64),162,None).await?.delivery_revision,2);
        tx.commit().await?;
        Ok(())
    }).await;
    current.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_organizations_notification_reissue_is_atomic_fenced_and_idempotent_after_key_rotation(
) -> TestResult {
    let current = CurrentFixture::new().await?;
    let f = &current.fixture;
    let result = current.run(async {
        let (old_ring, selection) = configure(f).await?;
        let scope = f.base.organization.scope;
        let mut tx = f.base.pool.begin().await?;
        let invitation = invite::issue_first_admin(&mut tx, f.issuance()).await?;
        tx.commit().await?;
        let mut tx = f.base.pool.begin().await?;
        let first = queue::claim(&mut tx, scope.environment_id, selection, Uuid::new_v4(), 1, 100).await?.remove(0);
        tx.commit().await?;
        let mut tx = f.base.pool.begin().await?;
        let admitted = invite::durable::admit_current(&mut tx, scope, &first, selection, &"a".repeat(64), 101, None).await?;
        tx.commit().await?;
        let first_bytes = admitted.open(&old_ring, 102)?;
        let first_payload: serde_json::Value = serde_json::from_slice(&first_bytes)?;
        let before = proof_row(f, invitation.id).await?;
        let (new_ring, _) = configure_version(f, "delivery_2", 2).await?;
        let command = Reissue {
            scope, invitation: invitation.id, challenge: None, identity_request: None,
            expected_delivery_revision: 1, operation: Uuid::new_v4(),
        };
        // Wrong credential, stale proof revision and a premature explicit reissue
        // all refuse without changing either the proof or its queued message.
        for variant in 0..3 {
            let mut input = command.clone();
            if variant == 1 { input.expected_delivery_revision = 0; }
            let mut tx = f.base.pool.begin().await?;
            let credential = if variant == 0 { "b".repeat(64) } else { "a".repeat(64) };
            let now = if variant == 2 { 120 } else { 161 };
            assert!(reissue(&mut tx, &input, &credential, now, None).await.is_err());
            tx.rollback().await?;
            assert_eq!(proof_row(f, invitation.id).await?, before);
        }
        // A full retained-record allowance refuses successor creation. The caller
        // rolls the entire business transaction back, including supersession.
        let mut tx = f.base.pool.begin().await?;
        sqlx::query("UPDATE aegaeon.notification_queue_capacity SET retained_messages=100000 WHERE environment_id=$1")
            .bind(scope.environment_id).execute(&mut *tx).await?;
        assert!(reissue(&mut tx, &command, &"a".repeat(64), 161, None).await.is_err());
        tx.rollback().await?;
        assert_eq!(proof_row(f, invitation.id).await?, before);
        let still_secret: bool = sqlx::query_scalar("SELECT encrypted_payload IS NOT NULL AND state='leased' FROM aegaeon.notification_messages WHERE id=$1")
            .bind(first.message_id).fetch_one(&f.base.pool).await?;
        assert!(still_secret);
        let mut tx = f.base.pool.begin().await?;
        let replacement = reissue(&mut tx, &command, &"a".repeat(64), 161, None).await?;
        tx.commit().await?;
        assert_ne!(replacement.message_id, first.message_id);
        assert_eq!(replacement.expires_at, invitation.expires_at);
        assert_eq!(replacement.delivery_revision, 2);
        let mut tx = f.base.pool.begin().await?;
        let repeated = reissue(&mut tx, &command, &"a".repeat(64), 161, None).await?;
        tx.commit().await?;
        assert!(repeated == replacement);
        assert_eq!(messages(f).await?, 2);
        let old: (String, Option<String>, String) = sqlx::query_as("SELECT state,encrypted_payload,terminal_reason FROM aegaeon.notification_messages WHERE id=$1")
            .bind(first.message_id).fetch_one(&f.base.pool).await?;
        assert_eq!(old, ("terminal".into(), None, "superseded".into()));
        let mut tx = f.base.pool.begin().await?;
        assert!(queue::complete(&mut tx, &first, CompletedAttempt {
            attempts: 1, observed_at: 162, outcome: TransportOutcome::Accepted, retry_after: None,
        }, 0).await.is_err());
        tx.rollback().await?;
        let mut tx = f.base.pool.begin().await?;
        let second = queue::claim(&mut tx, scope.environment_id, selection, Uuid::new_v4(), 1, 162).await?.remove(0);
        tx.commit().await?;
        assert_eq!(second.message_id, replacement.message_id);
        let mut tx = f.base.pool.begin().await?;
        let authorized = invite::durable::admit_current(&mut tx, scope, &second, selection, &"a".repeat(64), 163, None).await?;
        tx.commit().await?;
        assert!(authorized.open(&old_ring, 164).is_err());
        let second_bytes = authorized.open(&new_ring, 164)?;
        let second_payload: serde_json::Value = serde_json::from_slice(&second_bytes)?;
        let (_, current_hash) = proof_row(f, invitation.id).await?;
        let current_hash: [u8; 32] = current_hash.try_into().map_err(|_| "invalid proof hash")?;
        let binding = cap::Binding { scope, object_id: invitation.id, delivery_revision: 2, purpose: cap::Purpose::Invitation };
        assert!(!cap::matches(binding, &current_hash, first_payload["capability"].as_str().unwrap()));
        assert!(cap::matches(binding, &current_hash, second_payload["capability"].as_str().unwrap()));
        assert_eq!(first_payload["expiresAt"], second_payload["expiresAt"]);
        assert_eq!(first_payload["recipient"], second_payload["recipient"]);
        let counts: (i32, i32) = sqlx::query_as("SELECT active_messages,retained_messages FROM aegaeon.notification_queue_capacity WHERE environment_id=$1")
            .bind(scope.environment_id).fetch_one(&f.base.pool).await?;
        assert_eq!(counts, (1, 2));
        Ok(())
    }).await;
    current.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_organizations_notification_legacy_hash_requires_explicit_reissue() -> TestResult {
    let current = CurrentFixture::new().await?;
    let f = &current.fixture;
    let result = current
        .run(async {
            let mut tx = f.base.pool.begin().await?;
            let invitation = invite::issue_first_admin(&mut tx, f.issuance()).await?;
            let legacy = invite::claim_invitation_delivery(
                &mut tx,
                f.base.organization.scope,
                invitation.id,
                100,
            )
            .await?;
            tx.commit().await?;
            let before = proof_row(f, invitation.id).await?;
            assert_eq!(messages(f).await?, 0);
            configure(f).await?;
            assert_eq!(messages(f).await?, 0);
            assert_eq!(proof_row(f, invitation.id).await?, before);
            let mut tx = f.base.pool.begin().await?;
            let result = reissue(
                &mut tx,
                &Reissue {
                    scope: f.base.organization.scope,
                    invitation: invitation.id,
                    challenge: None,
                    identity_request: None,
                    expected_delivery_revision: 1,
                    operation: Uuid::new_v4(),
                },
                &"a".repeat(64),
                161,
                None,
            )
            .await?;
            tx.commit().await?;
            assert_eq!(messages(f).await?, 1);
            assert_eq!(result.expires_at, invitation.expires_at);
            let (revision, hash) = proof_row(f, invitation.id).await?;
            let hash: [u8; 32] = hash.try_into().map_err(|_| "invalid proof hash")?;
            assert_eq!(revision, 2);
            assert!(!cap::matches(
                cap::Binding {
                    scope: f.base.organization.scope,
                    object_id: invitation.id,
                    delivery_revision: 2,
                    purpose: cap::Purpose::Invitation,
                },
                &hash,
                &legacy.capability.into_delivery()
            ));
            Ok(())
        })
        .await;
    current.finish(result).await
}
