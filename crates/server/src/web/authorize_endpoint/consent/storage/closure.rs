use super::*;
use crate::organizations::{
    repository_tests::Fixture, witness::tests::caller_fixture::CallerFixture,
};
use std::time::Duration;

fn session(subject: &str) -> AuthorizeSessionState {
    AuthorizeSessionState {
        session_id: Some("commit-closure-session".into()),
        set_cookie: None,
        auth_time_epoch_secs: 1,
        user_id: subject.into(),
        session_acr: None,
        claim_release_policy: None,
        original_authentication: None,
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual blocked consent creation and admission closure"]
async fn pg_organizations_consent_creation_rolls_back_when_admission_closes_before_commit(
) -> crate::web::test_support::TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
    let result = exercise(&f, &witness).await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() });
    f.cleanup(result.and(cleanup)).await
}

async fn exercise(f: &Fixture, witness: &CallerFixture) -> crate::web::test_support::TestResult {
    let state = crate::web::test_support::test_app_state(f.pool.clone(), &f.env).await?;
    let work = witness.begin().await?;
    let normal = work
        .store_scope(create(
            &state,
            &session("normal"),
            "/authorize",
            &serde_json::json!({}),
        ))
        .await?;
    assert!(normal.is_ok(), "open admission must create a consent");
    assert_eq!(work.complete().await?.pending, 0);

    let mut lock = f.pool.begin().await?;
    sqlx::query("LOCK TABLE aegaeon.authorization_consents IN SHARE MODE")
        .execute(&mut *lock)
        .await?;
    let work = witness.begin().await?;
    let owner = work.admission().clone();
    let pool = state.db_pool.clone();
    let caller = tokio::spawn(async move {
        let result = work
            .store_scope(create(
                &state,
                &session("closed"),
                "/authorize",
                &serde_json::json!({}),
            ))
            .await;
        (work, result)
    });
    let observed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database()
                 AND usename=current_user AND wait_event_type='Lock'
                 AND query LIKE '%DELETE FROM aegaeon.authorization_consents%')",
            )
            .fetch_one(&f.pool)
            .await?;
            if blocked {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    // Close before releasing the actual database statement; the create path
    // must roll back even though its request scope also refuses on exit.
    owner.close_until_restart();
    lock.rollback().await?;
    let (work, result) = tokio::time::timeout(Duration::from_secs(5), caller).await??;
    drop(work);
    drop(owner);
    pool.close().await;
    observed??;
    assert!(result.is_err(), "closed request scope must refuse");
    let retained: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.authorization_consents WHERE environment_id=$1 AND subject='closed'",
    )
    .bind(f.env.environment_id)
    .fetch_one(&f.pool)
    .await?;
    assert_eq!(
        retained, 0,
        "closed admission must not commit a consent row"
    );
    assert_eq!(witness.pending().await?, 1, "closed work stays pending");
    Ok(())
}
