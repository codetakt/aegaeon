use super::*;
use sqlx::Acquire;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_refusal_is_atomic_and_preserves_prior_uncertainty(
) -> TestResult {
    for prior_send in [false, true] {
        let f = QueueFixture::new().await?;
        let result = async {
            f.enqueue().await?;
            let mut at = 100;
            if prior_send {
                let first = f.claim(at).await?;
                f.admit(&first, at + 1).await?;
                let mut tx = f.base.pool.begin().await?;
                let plan = queue::complete(&mut tx, &first, CompletedAttempt {
                    attempts: 1, observed_at: 102, outcome: TransportOutcome::Uncertain,
                    retry_after: None,
                }, 0).await?;
                let crate::organizations::notification_retry::RetryPlan::At(next) = plan else {
                    panic!("expected retry");
                };
                at = i64::try_from(next)?;
                tx.commit().await?;
            }
            let claim = f.claim(at).await?;
            // A late authority refusal rolls back the provisional admission first.
            let mut tx = f.base.pool.begin().await?;
            let mut provisional = tx.begin().await?;
            queue::admit(&mut provisional, &claim, &f.context, f.selection, at + 1).await?;
            provisional.rollback().await?;
            queue::retire_not_admitted(&mut tx, &claim, f.selection, at + 2).await?;
            tx.rollback().await?;
            let before: (String, bool, bool, i32) = sqlx::query_as(
                "SELECT m.state,m.encrypted_payload IS NOT NULL,a.completed_at IS NULL,c.active_messages FROM aegaeon.notification_messages m JOIN aegaeon.notification_attempts a ON a.id=m.attempt_id JOIN aegaeon.notification_queue_capacity c ON c.environment_id=m.environment_id WHERE m.id=$1")
                .bind(claim.message_id).fetch_one(&f.base.pool).await?;
            assert_eq!(before, ("leased".into(), true, true, 1));
            let mut tx = f.base.pool.begin().await?;
            queue::retire_not_admitted(&mut tx, &claim, f.selection, at + 3).await?;
            tx.commit().await?;
            let stored: (String, String, bool, Option<String>, bool, i32, i32) = sqlx::query_as(
                "SELECT m.state,m.terminal_reason,m.encrypted_payload IS NULL,m.last_outcome,m.attempt_id IS NULL AND m.worker_id IS NULL AND m.lease_until IS NULL,c.active_messages,c.retained_messages FROM aegaeon.notification_messages m JOIN aegaeon.notification_queue_capacity c ON c.environment_id=m.environment_id WHERE m.id=$1")
                .bind(claim.message_id).fetch_one(&f.base.pool).await?;
            assert_eq!(stored, ("terminal".into(), "authority_changed".into(), true,
                prior_send.then(|| "uncertain".into()), true, 0, 1));
            let history: Vec<(String, bool)> = sqlx::query_as(
                "SELECT outcome,admitted_at IS NULL FROM aegaeon.notification_attempts WHERE message_id=$1 ORDER BY ordinal")
                .bind(claim.message_id).fetch_all(&f.base.pool).await?;
            let mut expected = Vec::new();
            if prior_send { expected.push(("uncertain".into(), false)); }
            expected.push(("not_admitted".into(), true));
            assert_eq!(history, expected);
            let mut tx = f.base.pool.begin().await?;
            assert!(queue::retire_not_admitted(&mut tx, &claim, f.selection, at + 4).await.is_err());
            tx.rollback().await?;
            Ok(())
        }.await;
        f.base.cleanup(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_refusal_rejects_expired_replaced_or_admitted_owners(
) -> TestResult {
    let f = QueueFixture::new().await?;
    let result = async {
        f.enqueue().await?;
        let old = f.claim(100).await?;
        let mut tx = f.base.pool.begin().await?;
        assert!(queue::retire_not_admitted(&mut tx, &old, f.selection, old.lease_until).await.is_err());
        tx.rollback().await?;
        let due: i64 = sqlx::query_scalar("SELECT available_at FROM aegaeon.notification_messages WHERE id=$1")
            .bind(old.message_id).fetch_one(&f.base.pool).await?;
        let current = f.claim(due).await?;
        let mut tx = f.base.pool.begin().await?;
        assert!(queue::retire_not_admitted(&mut tx, &old, f.selection, due).await.is_err());
        tx.rollback().await?;
        let changed = Selection::new(f.selection.deployment_id(), Uuid::new_v4())?;
        let mut tx = f.base.pool.begin().await?;
        assert!(queue::retire_not_admitted(&mut tx, &current, changed, due).await.is_err());
        tx.rollback().await?;
        f.admit(&current, due + 1).await?;
        let mut tx = f.base.pool.begin().await?;
        assert!(queue::retire_not_admitted(&mut tx, &current, f.selection, due + 2).await.is_err());
        tx.rollback().await?;
        let state: (String, bool, bool, bool, i32) = sqlx::query_as(
            "SELECT m.state,m.encrypted_payload IS NOT NULL,a.admitted_at IS NOT NULL,a.completed_at IS NULL,c.active_messages FROM aegaeon.notification_messages m JOIN aegaeon.notification_attempts a ON a.id=m.attempt_id JOIN aegaeon.notification_queue_capacity c ON c.environment_id=m.environment_id WHERE m.id=$1")
            .bind(current.message_id).fetch_one(&f.base.pool).await?;
        assert_eq!(state, ("leased".into(), true, true, true, 1));
        Ok(())
    }.await;
    f.base.cleanup(result).await
}
