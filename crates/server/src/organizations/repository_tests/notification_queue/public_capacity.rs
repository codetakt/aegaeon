use super::*;
use crate::organizations::{repository::RepositoryError, AuthorityError};

fn prepare(f: &QueueFixture, purpose: &str) -> Result<Prepared, RepositoryError> {
    let mut context = f.context.clone();
    context.message_id = Uuid::new_v4();
    context.purpose = purpose.to_owned();
    context.template = purpose.to_owned();
    Prepared::seal(
        context,
        Object {
            id: Uuid::new_v4(),
            parent: None,
        },
        &f.public_key,
        Zeroizing::new(b"one fixed secret proof".to_vec()),
        100,
    )
}

async fn counters(f: &QueueFixture) -> Result<(i32, i32, i32, i32), sqlx::Error> {
    sqlx::query_as(
        "SELECT active_messages, retained_messages, public_active_messages, public_retained_messages
         FROM aegaeon.notification_queue_capacity WHERE environment_id=$1",
    )
    .bind(f.base.env.environment_id)
    .fetch_one(&f.base.pool)
    .await
}

// Populate occupancy without sealing or delivering thousands of test proofs.
// The boundary enqueues below go through the real producer and PostgreSQL path.
pub(super) async fn seed(f: &QueueFixture, count: i32, terminal: bool) -> TestResult {
    let environment = f.base.env.environment_id;
    let mut tx = f.base.pool.begin().await?;
    sqlx::query(
        "INSERT INTO aegaeon.notification_queue_capacity(environment_id, active_messages, retained_messages, public_active_messages, public_retained_messages)
         VALUES ($1, $2, $3, $2, $3)",
    )
    .bind(environment)
    .bind(if terminal { 0 } else { count })
    .bind(count)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "WITH ids AS MATERIALIZED (SELECT gen_random_uuid() AS id FROM generate_series(1,$1))
         INSERT INTO aegaeon.notification_messages
           (id, environment_id, object_id, deployment_id, runtime_generation, purpose, key_version,
            context, encrypted_payload, created_at, expires_at, available_at, state, terminal_at, terminal_reason)
         SELECT id,$2,id,$3,$4,'password_recovery','fixture',
            $5::jsonb || jsonb_build_object('message_id',id::text,'purpose','password_recovery'),
            CASE WHEN $6 THEN NULL ELSE 'opaque fixture' END,100,4000,100,
            CASE WHEN $6 THEN 'terminal' ELSE 'pending' END,
            CASE WHEN $6 THEN 101 END, CASE WHEN $6 THEN 'accepted' END
         FROM ids",
    )
    .bind(count)
    .bind(environment)
    .bind(f.selection.deployment_id())
    .bind(f.selection.generation())
    .bind(serde_json::to_value(&f.context)?)
    .bind(terminal)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_public_active_last_slot_is_serialized(
) -> TestResult {
    let f = QueueFixture::new().await?;
    let result = async {
        seed(&f, 1_999, false).await?;
        let signup = prepare(&f, "public_registration")?;
        let recovery = prepare(&f, "password_recovery")?;
        let mut first = f.base.pool.begin().await?;
        let mut second = f.base.pool.begin().await?;
        queue::enqueue(&mut first, &signup).await?;
        {
            let competing = queue::enqueue(&mut second, &recovery);
            tokio::pin!(competing);
            let blocked =
                tokio::time::timeout(std::time::Duration::from_millis(50), &mut competing).await;
            assert!(blocked.is_err());
            first.commit().await?;
            assert!(matches!(
                competing.await,
                Err(RepositoryError::Authority(AuthorityError::Exhausted))
            ));
        }
        second.rollback().await?;
        f.enqueue().await?; // Authenticated contact verification uses physical capacity.
        assert_eq!(counters(&f).await?, (2_001, 2_001, 2_000, 2_000));
        Ok(())
    }
    .await;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_public_retained_limit_and_collection() -> TestResult
{
    let f = QueueFixture::new().await?;
    let result = async {
        seed(&f, 20_000, true).await?;
        let signup = prepare(&f, "public_registration")?;
        let mut tx = f.base.pool.begin().await?;
        assert!(matches!(
            queue::enqueue(&mut tx, &signup).await,
            Err(RepositoryError::Authority(AuthorityError::Exhausted))
        ));
        queue::enqueue(&mut tx, &prepare(&f, "contact_changed")?).await?;
        let at = 4000 + queue::RETENTION_SECONDS;
        assert_eq!(
            queue::collect_retained(&mut tx, f.base.env.environment_id, 1, at).await?,
            1
        );
        queue::enqueue(&mut tx, &signup).await?;
        tx.commit().await?;
        assert_eq!(counters(&f).await?, (2, 20_001, 1, 20_000));
        Ok(())
    }
    .await;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_notification_public_retirement_and_rollback() -> TestResult {
    let f = QueueFixture::new().await?;
    let result = async {
        let env = f.base.env.environment_id;
        let signup = prepare(&f, "public_registration")?;
        let mut tx = f.base.pool.begin().await?;
        queue::enqueue(&mut tx, &signup).await?;
        queue::enqueue(&mut tx, &f.prepared).await?;
        tx.commit().await?;
        assert_eq!(counters(&f).await?, (2, 2, 1, 1));
        let expiry = f.context.expires_at;
        let mut tx = f.base.pool.begin().await?;
        assert_eq!(
            queue::retire_ineligible(&mut tx, env, f.selection, 2, expiry)
                .await?
                .expired,
            2
        );
        tx.rollback().await?;
        assert_eq!(counters(&f).await?, (2, 2, 1, 1));
        let mut tx = f.base.pool.begin().await?;
        assert_eq!(
            queue::retire_ineligible(&mut tx, env, f.selection, 2, expiry)
                .await?
                .expired,
            2
        );
        tx.commit().await?;
        assert_eq!(counters(&f).await?, (0, 2, 0, 1));
        let mut tx = f.base.pool.begin().await?;
        assert_eq!(
            queue::collect_retained(&mut tx, env, 2, expiry + queue::RETENTION_SECONDS).await?,
            2
        );
        tx.commit().await?;
        assert_eq!(counters(&f).await?, (0, 0, 0, 0));
        Ok(())
    }
    .await;
    f.base.cleanup(result).await
}
