use super::*;

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_jit_reserved_subject_survives_rename_delete_and_environment_separation() -> TestResult {
    let f = Fixture::new().await?;
    let other = Fixture::new().await?;
    let subject = "upstream:v2:permanent-test-allocation";
    let id = f.local(subject, None).await?;
    sqlx::query(
        "UPDATE aegaeon.end_users SET status='SUSPENDED',email='changed@example.com' WHERE id=$1",
    )
    .bind(id)
    .execute(&f.pool)
    .await?;
    sqlx::query("UPDATE aegaeon.end_users SET subject=subject WHERE id=$1")
        .bind(id)
        .execute(&f.pool)
        .await?;
    sqlx::query("UPDATE aegaeon.end_users SET subject='renamed-local' WHERE id=$1")
        .bind(id)
        .execute(&f.pool)
        .await?;
    assert!(
        sqlx::query("UPDATE aegaeon.end_users SET subject=$2 WHERE id=$1")
            .bind(id)
            .bind(subject)
            .execute(&f.pool)
            .await
            .is_err()
    );
    sqlx::query("DELETE FROM aegaeon.end_users WHERE id=$1")
        .bind(id)
        .execute(&f.pool)
        .await?;
    assert!(f.local(subject, None).await.is_err());
    other.local(subject, None).await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.upstream_subject_reservations WHERE environment_id=$1 AND subject=$2").bind(f.env.environment_id).bind(subject).fetch_one(&f.pool).await?;
    assert_eq!(count, 1);
    other.cleanup().await?;
    f.cleanup().await
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_jit_concurrent_reserved_insert_then_soft_delete_refuses_contender() -> TestResult {
    let f = Fixture::new().await?;
    for deleted in [false, true] {
        let subject = format!("upstream:v2:concurrent-{deleted}");
        let mut first = f.pool.begin().await?;
        let id:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES($1,$2,'ACTIVE') RETURNING id").bind(f.env.environment_id).bind(&subject).fetch_one(&mut *first).await?;
        if deleted {
            sqlx::query("UPDATE aegaeon.end_users SET status='DELETED' WHERE id=$1")
                .bind(id)
                .execute(&mut *first)
                .await?;
        }
        let contender = sqlx::query(
            "INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES($1,$2,'ACTIVE')",
        )
        .bind(f.env.environment_id)
        .bind(&subject)
        .execute(&f.pool);
        tokio::pin!(contender);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut contender)
                .await
                .is_err(),
            "uncommitted reservation must hold the contender"
        );
        first.commit().await?;
        let failure = contender.await.expect_err("second allocation must fail");
        let database = failure.as_database_error().ok_or("database conflict")?;
        assert_eq!(database.code().as_deref(), Some("23505"));
        if deleted {
            assert_eq!(
                database.message(),
                "upstream subject allocation conflicts with an existing reservation"
            );
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1 AND subject=$2",
        )
        .bind(f.env.environment_id)
        .bind(&subject)
        .fetch_one(&f.pool)
        .await?;
        assert_eq!(count, 1);
    }
    f.cleanup().await
}
