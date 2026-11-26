mod public_capacity;
mod refusal;

use super::{Fixture, TestResult};
use crate::organizations::{
    lifecycle::Selection,
    notification_envelope::{
        KeyVersion, MessageContext, PrivateDeliveryKey, PrivateKeyRing, PublicDeliveryKey,
        Revision, Scope,
    },
    notification_outbox::{self as queue, Claim, Object, Prepared},
    notification_retry::{CompletedAttempt, TransportOutcome},
};
use aegaeon_crypto::hash::sha256_digest;
// Provider access below creates test-only key material.
#[cfg(test)]
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeySize, PrivateDecryptingKey},
};
use uuid::Uuid;
use zeroize::Zeroizing;

struct QueueFixture {
    base: Fixture,
    selection: Selection,
    context: MessageContext,
    prepared: Prepared,
    public_key: PublicDeliveryKey,
    ring: PrivateKeyRing,
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_claims_route_credentials_before_attempts(
) -> TestResult {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let f = QueueFixture::new().await?;
    let result = async {
        let environment = f.base.env.environment_id;
        let mut ids = Vec::new();
        // Domain enqueues and credential-bound claims still work at full public occupancy.
        public_capacity::seed(&f, 2_000, false).await?;
        // Two independently configured domains share one real PostgreSQL queue.
        // These are queue-state fixtures; purpose admission is tested separately.
        for digit in ['a', 'b'] {
            let domain = Uuid::new_v4();
            let material = PrivateDecryptingKey::generate(KeySize::Rsa2048)?;
            let public = material.public_key().as_der()?;
            let pin = sha256_digest(public.as_ref());
            let version = KeyVersion {
                id: format!("routing_{digit}"), deployment_id: f.selection.deployment_id(),
                scope: Scope::Domain { environment_id: environment, domain_id: domain },
                not_before: 0, seal_until: 5000, open_until: 6000,
            };
            let key = PublicDeliveryKey::new(version.clone(), public.as_ref(), pin)?;
            let channel = serde_json::json!({
                "endpoint":"https://delivery.example.test/envelopes",
                "credentialSha256":digit.to_string().repeat(64),
                "encryption":{"version":version.id,"deploymentId":version.deployment_id,
                    "publicSpki":URL_SAFE_NO_PAD.encode(public.as_ref()),
                    "spkiSha256":URL_SAFE_NO_PAD.encode(pin),"notBefore":0,
                    "sealUntil":5000,"openUntil":6000}
            });
            let mut context = f.context.clone();
            context.scope = version.scope;
            context.message_id = Uuid::new_v4();
            let message = Prepared::seal(context.clone(), Object { id: Uuid::new_v4(), parent: None },
                &key, Zeroizing::new(b"one fixed secret proof".to_vec()), 100)?;
            let mut tx = f.base.pool.begin().await?;
            sqlx::query("INSERT INTO aegaeon.authorization_domains(id,environment_id,name,enabled,invitation_delivery) VALUES($1,$2,$3,true,$4)")
                .bind(domain).bind(environment).bind(format!("routing-{digit}")).bind(channel)
                .execute(&mut *tx).await?;
            queue::enqueue(&mut tx, &message).await?;
            tx.commit().await?;
            ids.push((domain, context.message_id));
        }
        // More than the full retry budget of wrong-worker polls consumes none.
        for at in [100, 200, 300, 400, 500, 600] {
            let mut tx = f.base.pool.begin().await?;
            assert!(queue::claim_delivery(&mut tx, environment, f.selection, Uuid::new_v4(),
                &"c".repeat(64), 1, at).await?.is_empty());
            tx.commit().await?;
        }
        let untouched: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.notification_messages WHERE environment_id=$1 AND domain_id IS NOT NULL AND state='pending' AND attempts=0 AND fence=0 AND attempt_id IS NULL")
            .bind(environment).fetch_one(&f.base.pool).await?;
        assert_eq!(untouched, 2);
        let mut first = f.base.pool.begin().await?;
        let a = queue::claim_delivery(&mut first, environment, f.selection, Uuid::new_v4(),
            &"a".repeat(64), 1, 600).await?;
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].domain_id, a[0].message_id), (Some(ids[0].0), ids[0].1));
        let mut second = f.base.pool.begin().await?;
        // The second worker skips A's live lock, never stealing B's attempt.
        assert!(queue::claim_delivery(&mut second, environment, f.selection, Uuid::new_v4(),
            &"a".repeat(64), 1, 600).await?.is_empty());
        let b = queue::claim_delivery(&mut second, environment, f.selection, Uuid::new_v4(),
            &"b".repeat(64), 1, 600).await?;
        assert_eq!(b.len(), 1);
        assert_eq!((b[0].domain_id, b[0].message_id), (Some(ids[1].0), ids[1].1));
        second.commit().await?;
        first.commit().await?;
        let (claimed_domains, untouched_public): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE domain_id IS NOT NULL AND attempts=1),
                    count(*) FILTER (WHERE domain_id IS NULL AND state='pending' AND attempts=0
                        AND fence=0 AND attempt_id IS NULL AND lease_until IS NULL
                        AND encrypted_payload='opaque fixture')
             FROM aegaeon.notification_messages WHERE environment_id=$1",
        ).bind(environment).fetch_one(&f.base.pool).await?;
        assert_eq!((claimed_domains, untouched_public), (2, 2_000));
        Ok(())
    }.await;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_exhaustion_preserves_uncertainty_and_cleans_secret(
) -> TestResult {
    use crate::organizations::notification_retry::{RetryPlan, StopReason};
    for final_process_lost in [false, true] {
        let f = QueueFixture::new().await?;
        let result = async {
            f.enqueue().await?;
            let mut at = 100;
            for ordinal in 1..=5 {
                let claim = f.claim(at).await?;
                assert_eq!(claim.ordinal, ordinal);
                f.admit(&claim, at + 1).await?;
                let mut tx = f.base.pool.begin().await?;
                if ordinal == 5 && final_process_lost {
                    let retired = queue::retire_ineligible(
                        &mut tx, f.base.env.environment_id, f.selection, 1, claim.lease_until,
                    ).await?;
                    assert_eq!(retired.exhausted, 1);
                    assert_eq!(retired.total(), 1);
                    at = claim.lease_until;
                } else {
                    let plan = queue::complete(&mut tx, &claim, CompletedAttempt {
                        attempts: ordinal, observed_at: (at + 2) as u64,
                        outcome: TransportOutcome::Uncertain, retry_after: None,
                    }, 0).await?;
                    if ordinal < 5 {
                        let RetryPlan::At(next) = plan else { panic!("retry budget ended early"); };
                        at = i64::try_from(next)?;
                    } else {
                        assert_eq!(plan, RetryPlan::Stop(StopReason::AttemptsExhausted));
                    }
                }
                tx.commit().await?;
            }
            let row: (String, String, bool, i16) = sqlx::query_as(
                "SELECT terminal_reason,last_outcome,encrypted_payload IS NULL,attempts FROM aegaeon.notification_messages WHERE id=$1",
            ).bind(f.context.message_id).fetch_one(&f.base.pool).await?;
            assert_eq!(row, ("exhausted".into(), "uncertain".into(), true, 5));
            let mut tx = f.base.pool.begin().await?;
            assert!(queue::claim(&mut tx, f.base.env.environment_id, f.selection, Uuid::new_v4(), 1, at + 60).await?.is_empty());
            tx.commit().await?;
            let outcomes: Vec<String> = sqlx::query_scalar(
                "SELECT outcome FROM aegaeon.notification_attempts WHERE message_id=$1 ORDER BY ordinal",
            ).bind(f.context.message_id).fetch_all(&f.base.pool).await?;
            assert_eq!(outcomes, vec!["uncertain"; 5]);
            let active: i32 = sqlx::query_scalar(
                "SELECT active_messages FROM aegaeon.notification_queue_capacity WHERE environment_id=$1",
            ).bind(f.base.env.environment_id).fetch_one(&f.base.pool).await?;
            assert_eq!(active, 0);
            Ok(())
        }.await;
        f.base.cleanup(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_retention_waits_for_proof_expiry() -> TestResult {
    let f = QueueFixture::new().await?;
    let result = async {
        f.enqueue().await?;
        let claim = f.claim(100).await?;
        f.admit(&claim, 101).await?;
        let mut tx = f.base.pool.begin().await?;
        queue::complete(
            &mut tx,
            &claim,
            CompletedAttempt {
                attempts: 1,
                observed_at: 102,
                outcome: TransportOutcome::Accepted,
                retry_after: None,
            },
            0,
        ).await?;
        tx.commit().await?;
        let counters: (i32, i32) = sqlx::query_as("SELECT active_messages,retained_messages FROM aegaeon.notification_queue_capacity WHERE environment_id=$1")
            .bind(f.base.env.environment_id).fetch_one(&f.base.pool).await?;
        assert_eq!(counters, (0, 1));
        let mut tx = f.base.pool.begin().await?;
        assert_eq!(queue::collect_retained(&mut tx, f.base.env.environment_id, 1,
            queue::RETENTION_SECONDS + 3999).await?, 0);
        tx.commit().await?;
        let mut tx = f.base.pool.begin().await?;
        assert_eq!(queue::collect_retained(&mut tx, f.base.env.environment_id, 1,
            queue::RETENTION_SECONDS + 4000).await?, 1);
        tx.rollback().await?;
        let mut tx = f.base.pool.begin().await?;
        assert_eq!(queue::collect_retained(&mut tx, f.base.env.environment_id, 1,
            queue::RETENTION_SECONDS + 4000).await?, 1);
        tx.commit().await?;
        let counters: (i32, i32) = sqlx::query_as("SELECT active_messages,retained_messages FROM aegaeon.notification_queue_capacity WHERE environment_id=$1")
            .bind(f.base.env.environment_id).fetch_one(&f.base.pool).await?;
        assert_eq!(counters, (0, 0));
        let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.notification_attempts WHERE message_id=$1")
            .bind(f.context.message_id).fetch_one(&f.base.pool).await?;
        assert_eq!(attempts, 0);
        Ok(())
    }.await;
    f.base.cleanup(result).await
}

impl QueueFixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_expiry(4000).await
    }

    async fn with_expiry(expires_at: i64) -> Result<Self, Box<dyn std::error::Error>> {
        let base = Fixture::new().await?;
        let selection = Selection::new(Uuid::new_v4(), Uuid::new_v4())?;
        let material = PrivateDecryptingKey::generate(KeySize::Rsa2048)?;
        let public = material.public_key().as_der()?.as_ref().to_vec();
        let private = Zeroizing::new(material.as_der()?.as_ref().to_vec());
        let pin = sha256_digest(&public);
        let version = KeyVersion {
            id: "test_delivery_1".into(),
            deployment_id: selection.deployment_id(),
            scope: Scope::Environment {
                environment_id: base.env.environment_id,
            },
            not_before: 0,
            seal_until: 5000,
            open_until: 6000,
        };
        let key = PublicDeliveryKey::new(version.clone(), &public, pin)?;
        let ring = PrivateKeyRing::new(vec![PrivateDeliveryKey::new(version, private, pin)?])?;
        let payload = Zeroizing::new(b"one fixed secret proof".to_vec());
        let context = MessageContext {
            message_id: Uuid::new_v4(),
            deployment_id: selection.deployment_id(),
            runtime_generation: selection.generation(),
            scope: Scope::Environment {
                environment_id: base.env.environment_id,
            },
            organization_generation: Revision::NotApplicable,
            purpose: "contact_verification".into(),
            template: "contact_verification".into(),
            template_version: 1,
            expires_at,
            authority_revision: Revision::Value(1),
            contact_revision: Revision::Value(1),
            configuration_revision: Revision::Value(1),
            authority_binding: [1; 32],
            destination_binding: [2; 32],
            payload_digest: sha256_digest(&payload),
        };
        let prepared = Prepared::seal(
            context.clone(),
            Object {
                id: Uuid::new_v4(),
                parent: None,
            },
            &key,
            payload,
            100,
        )?;
        Ok(Self {
            base,
            selection,
            context,
            prepared,
            public_key: key,
            ring,
        })
    }

    async fn enqueue(&self) -> TestResult {
        let mut tx = self.base.pool.begin().await?;
        queue::enqueue(&mut tx, &self.prepared).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn claim(&self, now: i64) -> Result<Claim, Box<dyn std::error::Error>> {
        let mut tx = self.base.pool.begin().await?;
        let mut claims = queue::claim(
            &mut tx,
            self.base.env.environment_id,
            self.selection,
            Uuid::new_v4(),
            1,
            now,
        )
        .await?;
        assert_eq!(claims.len(), 1);
        tx.commit().await?;
        Ok(claims.remove(0))
    }

    async fn admit(&self, claim: &Claim, now: i64) -> Result<String, Box<dyn std::error::Error>> {
        let mut tx = self.base.pool.begin().await?;
        let (version, ciphertext) =
            queue::admit(&mut tx, claim, &self.context, self.selection, now).await?;
        tx.commit().await?;
        assert_eq!(
            self.ring
                .open(&version, &self.context, &ciphertext, now)?
                .as_slice(),
            b"one fixed secret proof"
        );
        Ok(ciphertext)
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_crash_never_shortens_backoff_to_fit_expiry(
) -> TestResult {
    let f = QueueFixture::with_expiry(180).await?;
    let result = async {
        f.enqueue().await?;
        let claim = f.claim(100).await?;
        assert_eq!(claim.lease_until, 145);
        f.admit(&claim, 101).await?;
        // The sender disappears without a completion. Even at lease expiry,
        // another attempt must honor the minimum 60-second backoff.
        let available: i64 = sqlx::query_scalar(
            "SELECT available_at FROM aegaeon.notification_messages WHERE id=$1",
        )
        .bind(f.context.message_id)
        .fetch_one(&f.base.pool)
        .await?;
        assert_eq!(available, 180);
        for now in [144, 145, 179, 180] {
            let mut tx = f.base.pool.begin().await?;
            assert!(queue::claim(
                &mut tx,
                f.base.env.environment_id,
                f.selection,
                Uuid::new_v4(),
                1,
                now,
            )
            .await?
            .is_empty());
            tx.commit().await?;
        }
        let mut tx = f.base.pool.begin().await?;
        assert_eq!(queue::retire_ineligible(
            &mut tx, f.base.env.environment_id, f.selection, 1, 180,
        ).await?.total(), 1);
        tx.commit().await?;
        let row: (String, Option<String>, String, String) = sqlx::query_as(
            "SELECT state,encrypted_payload,last_outcome,terminal_reason FROM aegaeon.notification_messages WHERE id=$1",
        ).bind(f.context.message_id).fetch_one(&f.base.pool).await?;
        assert_eq!(row, ("terminal".into(), None, "uncertain".into(), "expired".into()));
        let attempts: Vec<String> = sqlx::query_scalar(
            "SELECT outcome FROM aegaeon.notification_attempts WHERE message_id=$1 ORDER BY ordinal",
        ).bind(f.context.message_id).fetch_all(&f.base.pool).await?;
        assert_eq!(attempts, ["uncertain"]);
        let active: i32 = sqlx::query_scalar(
            "SELECT active_messages FROM aegaeon.notification_queue_capacity WHERE environment_id=$1",
        ).bind(f.base.env.environment_id).fetch_one(&f.base.pool).await?;
        assert_eq!(active, 0);
        Ok(())
    }.await;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_retries_keep_ciphertext_and_fence_late_owners(
) -> TestResult {
    let f = QueueFixture::new().await?;
    let result=async{
        f.enqueue().await?;
        let first=f.claim(100).await?;
        let ciphertext=f.admit(&first,101).await?;
        let mut tx=f.base.pool.begin().await?;
        queue::complete(&mut tx,&first,CompletedAttempt{attempts:1,observed_at:102,outcome:TransportOutcome::Uncertain,retry_after:None},0).await?;
        tx.commit().await?;
        let mut tx=f.base.pool.begin().await?;
        assert!(queue::claim(&mut tx,f.base.env.environment_id,f.selection,Uuid::new_v4(),1,161).await?.is_empty());
        tx.commit().await?;
        let second=f.claim(162).await?;
        assert_ne!(first.attempt_id,second.attempt_id);
        assert_eq!(second.fence,first.fence+1);
        assert_eq!(f.admit(&second,163).await?,ciphertext);
        let mut tx=f.base.pool.begin().await?;
        assert!(queue::complete(&mut tx,&first,CompletedAttempt{attempts:1,observed_at:164,outcome:TransportOutcome::Accepted,retry_after:None},0).await.is_err());
        tx.rollback().await?;
        let mut tx=f.base.pool.begin().await?;
        queue::complete(&mut tx,&second,CompletedAttempt{attempts:2,observed_at:164,outcome:TransportOutcome::Accepted,retry_after:None},0).await?;
        tx.commit().await?;
        let row:(String,Option<String>,String)=sqlx::query_as("SELECT state,encrypted_payload,last_outcome FROM aegaeon.notification_messages WHERE id=$1").bind(f.context.message_id).fetch_one(&f.base.pool).await?;
        assert_eq!(row,("terminal".into(),None,"accepted".into()));
        let count:i32=sqlx::query_scalar("SELECT active_messages FROM aegaeon.notification_queue_capacity WHERE environment_id=$1").bind(f.base.env.environment_id).fetch_one(&f.base.pool).await?;
        assert_eq!(count,0);
        let observations:Vec<String>=sqlx::query_scalar("SELECT outcome FROM aegaeon.notification_attempts WHERE message_id=$1 ORDER BY ordinal").bind(f.context.message_id).fetch_all(&f.base.pool).await?;
        assert_eq!(observations,["uncertain","accepted"]);
        Ok(())
    }.await;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_claims_skip_locks_and_rollback_all_capacity(
) -> TestResult {
    let f = QueueFixture::new().await?;
    let result = async {
        let mut transaction = f.base.pool.begin().await?;
        queue::enqueue(&mut transaction, &f.prepared).await?;
        transaction.rollback().await?;
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM aegaeon.notification_messages WHERE id=$1")
                .bind(f.context.message_id)
                .fetch_one(&f.base.pool)
                .await?;
        assert_eq!(count, 0);
        f.enqueue().await?;
        let mut first = f.base.pool.begin().await?;
        let claims = queue::claim(
            &mut first,
            f.base.env.environment_id,
            f.selection,
            Uuid::new_v4(),
            1,
            100,
        )
        .await?;
        assert_eq!(claims.len(), 1);
        let mut second = f.base.pool.begin().await?;
        let other = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            queue::claim(
                &mut second,
                f.base.env.environment_id,
                f.selection,
                Uuid::new_v4(),
                1,
                100,
            ),
        )
        .await??;
        assert!(other.is_empty());
        second.rollback().await?;
        first.rollback().await?;
        let claim = f.claim(100).await?;
        assert_eq!(claim.ordinal, 1);
        assert_eq!(claim.fence, 1);
        Ok(())
    }
    .await;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_changed_generation_and_context_refuse_send(
) -> TestResult {
    let f = QueueFixture::new().await?;
    let result=async{
        f.enqueue().await?;
        let claim=f.claim(100).await?;
        let changed=Selection::new(f.selection.deployment_id(),Uuid::new_v4())?;
        let mut tx=f.base.pool.begin().await?;
        assert!(queue::admit(&mut tx,&claim,&f.context,changed,101).await.is_err());
        tx.rollback().await?;
        let mut context=f.context.clone();
        context.contact_revision=Revision::Value(2);
        let mut tx=f.base.pool.begin().await?;
        assert!(queue::admit(&mut tx,&claim,&context,f.selection,101).await.is_err());
        tx.rollback().await?;
        let mut tx=f.base.pool.begin().await?;
        assert_eq!(queue::retire_ineligible(&mut tx,f.base.env.environment_id,changed,1,102).await?.total(),1);
        tx.commit().await?;
        let mut tx=f.base.pool.begin().await?;
        assert!(queue::admit(&mut tx,&claim,&f.context,f.selection,103).await.is_err());
        tx.rollback().await?;
        let row:(String,Option<String>)=sqlx::query_as("SELECT terminal_reason,encrypted_payload FROM aegaeon.notification_messages WHERE id=$1").bind(f.context.message_id).fetch_one(&f.base.pool).await?;
        assert_eq!(row,("generation_changed".into(),None));
        Ok(())
    }.await;
    f.base.cleanup(result).await
}
