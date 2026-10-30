//! ORG-R02 / ORG-G02 / ORG-P02, ORG-P13: real permanent-owner boundary.
use super::*;
use crate::web::test_support::test_admin_pool;

#[tokio::test]
#[ignore = "requires PostgreSQL; actual catalog privilege and constraint corruption"]
async fn pg_organizations_catalog_refuses_unsafe_grants_and_changed_foreign_key() -> TestResult {
    let f = Fixture::new().await?;
    let admin = test_admin_pool(&f.pool).await?;
    let runtime: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&f.pool)
        .await?;
    let result = async {
        crate::web::namespace_runtime::validate_database_inputs(&f.pool,f.env.environment_id,&f.env.issuer_url).await?;
        // Roll back each controlled fault before observing the next one.
        for privilege in ["DELETE", "UPDATE(external_id)"] {
            let mut tx = admin.begin().await?;
            let query = format!("GRANT {privilege} ON aegaeon.application_organizations TO \"{}\"",runtime.replace('"',"\"\""));
            sqlx::query(&query).execute(&mut *tx).await?;
            assert!(sqlx::query("SELECT aegaeon.subject_history_preflight($1)").bind(&runtime)
                .execute(&mut *tx).await.is_err(),"{privilege}");
            tx.rollback().await?;
        }
        for query in [
            "ALTER TABLE aegaeon.organization_memberships DROP CONSTRAINT organization_memberships_end_user_id_environment_id_fkey",
            "DROP INDEX aegaeon.authorization_domains_one_default",
        ] {
            let mut tx = admin.begin().await?;
            sqlx::query(query).execute(&mut *tx).await?;
            assert!(sqlx::query("SELECT aegaeon.subject_history_preflight($1)").bind(&runtime)
                .execute(&mut *tx).await.is_err(),"{query}");
            tx.rollback().await?;
        }
        crate::web::namespace_runtime::validate_database_inputs(&f.pool,f.env.environment_id,&f.env.issuer_url).await?;
        Ok(())
    }.await;
    admin.close().await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and permanent ownership migrations"]
async fn pg_organizations_user_deletion_retains_membership_without_authority() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let access = f.access().await?;
        sqlx::query("DELETE FROM aegaeon.end_users WHERE id=$1")
            .bind(f.users[0]).execute(&f.pool).await?;
        let mut tx = f.pool.begin().await?;
        let retained = repository::membership(&mut tx, &f.organization, f.users[0])
            .await?.ok_or("history missing")?;
        assert_eq!(retained.state, MembershipState::Active);
        assert!(matches!(repository::require_active_identity(&mut tx,
            f.organization.scope, f.users[0], Some(&access.binding.subject)).await,
            Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        tx.rollback().await?;
        assert!(matches!(f.delegate(&access, "deleted-user-replay").await,
            Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        let admin = test_admin_pool(&f.pool).await?;
        let retained: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM aegaeon.end_user_identity_owners WHERE owner_id=$1 AND environment_id=$2)")
            .bind(f.users[0]).bind(f.env.environment_id).fetch_one(&admin).await?;
        assert!(retained);
        admin.close().await;
        // Same UUID cannot acquire a new identity even after physical deletion.
        assert!(sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')")
            .bind(f.users[0]).bind(f.env.environment_id).bind(Uuid::new_v4().to_string())
            .execute(&f.pool).await.is_err());
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and permanent ownership migrations"]
async fn pg_organizations_membership_requires_owner_in_same_environment() -> TestResult {
    let f = Fixture::new().await?;
    let foreign = Fixture::new().await?;
    let result = async {
        for user in [foreign.users[0], Uuid::new_v4()] {
            let error = sqlx::query("INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,end_user_id,incarnation,state,roles) VALUES($1,$2,$3,$4,$5,'active','[]')")
                .bind(f.env.environment_id).bind(f.organization.scope.domain_id)
                .bind(f.organization.id).bind(user).bind(Uuid::new_v4())
                .execute(&f.pool).await.expect_err("unowned or foreign owner");
            assert_eq!(error.as_database_error().and_then(|e| e.code()).as_deref(),Some("23503"));
        }
        Ok(())
    }.await;
    foreign.cleanup(Ok(())).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL organization grants"]
async fn pg_organizations_runtime_cannot_erase_history_or_replace_identifiers() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        for query in [
            "DELETE FROM aegaeon.organization_memberships WHERE false",
            "DELETE FROM aegaeon.application_organizations WHERE false",
            "UPDATE aegaeon.application_organizations SET external_id='replacement' WHERE false",
            "UPDATE aegaeon.organization_memberships SET end_user_id=gen_random_uuid() WHERE false",
            "UPDATE aegaeon.organization_memberships SET incarnation=gen_random_uuid() WHERE false",
            "UPDATE aegaeon.organization_authority_events SET data='{}' WHERE false",
            "UPDATE aegaeon.organization_authority_receipts SET result='{}' WHERE false",
            "TRUNCATE aegaeon.organization_authority_outbox",
        ] {
            let mut tx = f.pool.begin().await?;
            let error = sqlx::query(query)
                .execute(&mut *tx)
                .await
                .expect_err("runtime mutation refused");
            assert_eq!(
                error.as_database_error().and_then(|e| e.code()).as_deref(),
                Some("42501"),
                "{query}"
            );
            tx.rollback().await?;
        }
        f.access().await?;
        Ok(())
    }
    .await;
    f.cleanup(result).await
}
