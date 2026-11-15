//! Read-only discovery transactions coexist but retain the mutation fence.
use super::*;
use crate::organizations::{discovery, repository, Scope};
use sqlx::{Postgres, Transaction};

async fn bounded_transaction(f: &Fixture) -> TestResult<Transaction<'_, Postgres>> {
    let mut tx = f.pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='500ms'")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn writer_blocked(f: &Fixture, scope: Scope) -> TestResult {
    let mut tx = bounded_transaction(f).await?;
    let result = repository::lock_organization(&mut tx, scope, f.organization.id).await;
    tx.rollback().await?;
    assert!(
        matches!(result, Err(repository::RepositoryError::Storage(sqlx::Error::Database(ref error))) if error.code().as_deref()==Some("55P03")),
        "writer must wait for discovery readers: {result:?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_readers_coexist_and_fence_writers() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let result = fixture::in_epoch(
        &state,
        Box::pin(async {
            let subject = format!("organization-user-{}", f.users[1]);
            let audience = format!("{}/organizations", state.issuer);
            let dedicated = format!("{}/organization-discovery", state.issuer);
            let query = discovery::Query {
                environment_id: state.environment_id,
                issuer: &state.issuer,
                client_id: OWNER,
                subject: &subject,
                auth_time: i64::try_from(crate::util::now_unix_epoch_secs()?)?,
                dpop_jkt: "read-fixture",
                audience: &audience,
                privileges: None,
                discovery_audience: Some(&dedicated),
                cursor: None,
            };
            let mut first = bounded_transaction(&f).await?;
            let first_page = discovery::page(&mut first, &query).await?;
            assert_eq!(first_page.organizations.len(), 1);
            let mut second = bounded_transaction(&f).await?;
            // This reaches the actual page's initial and per-row locks while the
            // first complete page still retains every read lock in its transaction.
            let second_page = discovery::page(&mut second, &query).await;
            if second_page.is_err() {
                first.rollback().await?;
                second.rollback().await?;
                return Err(format!("second discovery reader refused: {second_page:?}").into());
            }
            assert_eq!(first_page, second_page?);
            let mut permission = bounded_transaction(&f).await?;
            assert_eq!(
                discovery::token_permission(
                    &mut permission,
                    state.environment_id,
                    OWNER,
                    &dedicated
                )
                .await?,
                f.organization.scope
            );
            permission.rollback().await?;
            writer_blocked(&f, f.organization.scope).await?;
            first.rollback().await?;
            writer_blocked(&f, f.organization.scope).await?;
            second.rollback().await?;
            let mut writer = bounded_transaction(&f).await?;
            repository::lock_organization(&mut writer, f.organization.scope, f.organization.id)
                .await?;
            writer.rollback().await?;
            Ok(())
        }),
    )
    .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
