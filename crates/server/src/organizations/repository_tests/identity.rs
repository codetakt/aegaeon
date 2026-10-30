use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_identity_generation_credentials_and_rollback_guards() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let user = f.users[1];
        let state = |id| {
            sqlx::query_as::<_, (i64, i64)>("SELECT organization_identity_revision,organization_reauthentication_after FROM aegaeon.end_users WHERE id=$1").bind(id)
        };
        let original = state(user).fetch_one(&f.pool).await?;
        let other = state(f.users[0]).fetch_one(&f.pool).await?;
        assert_eq!(original, (1, 0));
        let credential = Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(id,end_user_id,password_hash) VALUES($1,$2,'unused-identity-trigger-fixture')")
            .bind(credential).bind(user).execute(&f.pool).await?;
        let created = state(user).fetch_one(&f.pool).await?;
        assert_eq!(created.0, 2);
        assert!(created.1 > 0);
        // Routine use/profile updates neither revoke nor resurrect authority.
        sqlx::query("UPDATE aegaeon.end_user_password_credentials SET last_used_at=now() WHERE id=$1")
            .bind(credential).execute(&f.pool).await?;
        sqlx::query("UPDATE aegaeon.end_users SET updated_at=now() WHERE id=$1")
            .bind(user).execute(&f.pool).await?;
        assert_eq!(state(user).fetch_one(&f.pool).await?, created);
        assert!(sqlx::query("UPDATE aegaeon.end_user_password_credentials SET end_user_id=$2 WHERE id=$1")
            .bind(credential).bind(f.users[0]).execute(&f.pool).await.is_err());
        for command in [
            "UPDATE aegaeon.end_user_password_credentials SET password_hash='unused-replacement-fixture' WHERE id=$1",
            "UPDATE aegaeon.end_user_password_credentials SET status='REVOKED' WHERE id=$1",
            "DELETE FROM aegaeon.end_user_password_credentials WHERE id=$1",
        ] {
            let previous = state(user).fetch_one(&f.pool).await?;
            sqlx::query(command).bind(credential).execute(&f.pool).await?;
            let current = state(user).fetch_one(&f.pool).await?;
            assert_eq!(current.0, previous.0 + 1);
            assert!(current.1 >= previous.1);
        }
        let before = state(user).fetch_one(&f.pool).await?;
        for command in [
            "UPDATE aegaeon.end_users SET organization_identity_revision=1 WHERE id=$1",
            "UPDATE aegaeon.end_users SET organization_reauthentication_after=0 WHERE id=$1",
        ] {
            assert!(sqlx::query(command).bind(user).execute(&f.pool).await.is_err());
            assert_eq!(state(user).fetch_one(&f.pool).await?, before);
        }
        // The cutoff is exclusive, including the same timestamp second.
        let subject = format!("organization-user-{user}");
        let mut tx = f.pool.begin().await?;
        assert!(super::super::identity::revision(&mut tx, f.organization.scope, user, &subject, before.1).await.is_err());
        assert_eq!(super::super::identity::revision(&mut tx, f.organization.scope, user, &subject, before.1 + 1).await?, before.0);
        tx.rollback().await?;
        // A future cutoff survives status transitions (including clock rollback).
        let future = before.1 + 3600;
        sqlx::query("UPDATE aegaeon.end_users SET organization_reauthentication_after=$2,organization_identity_revision=9223372036854775807 WHERE id=$1")
            .bind(user).bind(future).execute(&f.pool).await?;
        for status in ["SUSPENDED", "ACTIVE"] {
            sqlx::query("UPDATE aegaeon.end_users SET status=$2::aegaeon.end_user_status WHERE id=$1")
                .bind(user).bind(status).execute(&f.pool).await?;
            assert_eq!(state(user).fetch_one(&f.pool).await?, (i64::MAX, future));
        }
        let mut tx = f.pool.begin().await?;
        assert!(super::super::identity::revision(&mut tx, f.organization.scope, user, &subject, future + 1).await.is_err());
        tx.rollback().await?;
        assert_eq!(state(f.users[0]).fetch_one(&f.pool).await?, other);
        Ok(())
    }.await;
    f.cleanup(result).await
}
