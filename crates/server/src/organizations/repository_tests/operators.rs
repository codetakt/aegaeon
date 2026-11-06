use super::*;
use crate::organizations::operators::{lock_operator_authority, Capability};

pub(super) async fn principal(f: &Fixture) -> TestResult {
    sqlx::query("INSERT INTO aegaeon.administrators(id,email,password_hash,kind,status) VALUES ($1,$2,'synthetic-unused-hash','HUMAN','ACTIVE')")
        .bind(f.actor.id).bind(format!("{}@operator.example",f.actor.id)).execute(&f.pool).await?;
    sqlx::query("INSERT INTO aegaeon.team_memberships(team_id,administrator_id,role) VALUES ($1,$2,'OWNER')")
        .bind(f.env.team_id).bind(f.actor.id).execute(&f.pool).await?;
    Ok(())
}

pub(super) async fn grant(f: &Fixture, values: serde_json::Value) -> TestResult {
    sqlx::query("INSERT INTO aegaeon.organization_operator_grants(id,environment_id,domain_id,administrator_id,capabilities,active) VALUES ($1,$2,$3,$4,$5,true)")
        .bind(Uuid::new_v4()).bind(f.organization.scope.environment_id)
        .bind(f.organization.scope.domain_id).bind(f.actor.id).bind(values).execute(&f.pool).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_operator_owner_has_no_implicit_domain_capability() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        principal(&f).await?;
        let mut tx = f.pool.begin().await?;
        assert!(lock_operator_authority(
            &mut tx,
            f.organization.scope,
            f.env.team_id,
            f.actor.id,
            Capability::Provision
        )
        .await
        .is_err());
        tx.rollback().await?;
        grant(&f, serde_json::json!(["reconcile"])).await?;
        for capability in [
            Capability::Configure,
            Capability::Provision,
            Capability::Export,
            Capability::Support,
        ] {
            let mut tx = f.pool.begin().await?;
            assert!(lock_operator_authority(
                &mut tx,
                f.organization.scope,
                f.env.team_id,
                f.actor.id,
                capability
            )
            .await
            .is_err());
            tx.rollback().await?;
        }
        let mut tx = f.pool.begin().await?;
        let authority = lock_operator_authority(
            &mut tx,
            f.organization.scope,
            f.env.team_id,
            f.actor.id,
            Capability::Reconcile,
        )
        .await?;
        assert_eq!(authority.principal(), f.actor.id);
        assert_eq!(authority.revision(), 1);
        assert!(!authority.grant().is_nil());
        tx.rollback().await?;
        for (scope, team, user) in [
            (f.organization.scope, Uuid::new_v4(), f.actor.id),
            (
                Scope {
                    domain_id: Uuid::new_v4(),
                    ..f.organization.scope
                },
                f.env.team_id,
                f.actor.id,
            ),
            (
                Scope {
                    environment_id: Uuid::new_v4(),
                    ..f.organization.scope
                },
                f.env.team_id,
                f.actor.id,
            ),
            (f.organization.scope, f.env.team_id, f.users[0]),
        ] {
            let mut tx = f.pool.begin().await?;
            assert!(
                lock_operator_authority(&mut tx, scope, team, user, Capability::Reconcile)
                    .await
                    .is_err()
            );
            tx.rollback().await?;
        }
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_operator_rechecks_lifecycle_and_rejects_malformed_grants() -> TestResult {
    let f = Fixture::new().await?;
    let result=async {
        principal(&f).await?;
        grant(&f,serde_json::json!(["configure","reconcile"])).await?;
        for query in [
            "UPDATE aegaeon.administrators SET status='DISABLED' WHERE id=$1",
            "UPDATE aegaeon.administrators SET kind='SERVICE' WHERE id=$1",
            "UPDATE aegaeon.organization_operator_grants SET active=false WHERE administrator_id=$1",
            "UPDATE aegaeon.organization_operator_grants SET capabilities='[\"reconcile\",\"reconcile\"]' WHERE administrator_id=$1",
            "DELETE FROM aegaeon.team_memberships WHERE administrator_id=$1",
        ] {
            let mut tx=f.pool.begin().await?;
            sqlx::query(query).bind(f.actor.id).execute(&mut *tx).await?;
            assert!(lock_operator_authority(&mut tx,f.organization.scope,f.env.team_id,f.actor.id,Capability::Reconcile).await.is_err(),"{query}");
            tx.rollback().await?;
        }
        let mut tx=f.pool.begin().await?;
        sqlx::query("UPDATE aegaeon.authorization_domains SET enabled=false WHERE id=$1")
            .bind(f.organization.scope.domain_id).execute(&mut *tx).await?;
        assert!(lock_operator_authority(&mut tx,f.organization.scope,f.env.team_id,f.actor.id,Capability::Reconcile).await.is_err());
        assert!(lock_operator_authority(&mut tx,f.organization.scope,f.env.team_id,f.actor.id,Capability::Configure).await.is_ok());
        tx.rollback().await?;
        let mut tx=f.pool.begin().await?;
        assert!(lock_operator_authority(&mut tx,f.organization.scope,f.env.team_id,f.actor.id,Capability::Reconcile).await.is_ok());
        tx.rollback().await?;
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_operator_revocation_waits_for_admitted_transaction() -> TestResult {
    let f = Fixture::new().await?;
    let result=async {
        principal(&f).await?;
        grant(&f,serde_json::json!(["reconcile"])).await?;
        let mut admitted=f.pool.begin().await?;
        lock_operator_authority(&mut admitted,f.organization.scope,f.env.team_id,f.actor.id,Capability::Reconcile).await?;
        let mut revoke=f.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *revoke).await?;
        let failure=sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false,revision=revision+1 WHERE administrator_id=$1")
            .bind(f.actor.id).execute(&mut *revoke).await.unwrap_err();
        assert!(matches!(failure,sqlx::Error::Database(ref error) if error.code().as_deref()==Some("55P03")));
        revoke.rollback().await?;
        admitted.commit().await?;
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false,revision=revision+1 WHERE administrator_id=$1")
            .bind(f.actor.id).execute(&f.pool).await?;
        let mut later=f.pool.begin().await?;
        assert!(lock_operator_authority(&mut later,f.organization.scope,f.env.team_id,f.actor.id,Capability::Reconcile).await.is_err());
        later.rollback().await?;
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and privileged isolated fault fixture"]
async fn pg_organizations_operator_catalog_preserves_identity_and_rejects_corruption() -> TestResult
{
    let f = Fixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let runtime: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&f.pool)
        .await?;
    let result = async {
        principal(&f).await?;
        grant(&f,serde_json::json!(["reconcile"])).await?;
        for query in [
            "DELETE FROM aegaeon.organization_operator_grants WHERE administrator_id=$1",
            "UPDATE aegaeon.organization_operator_grants SET id=gen_random_uuid() WHERE administrator_id=$1",
        ] {
            let mut tx=f.pool.begin().await?;
            let error=sqlx::query(query).bind(f.actor.id).execute(&mut *tx).await.unwrap_err();
            assert!(matches!(error,sqlx::Error::Database(ref db) if db.code().as_deref()==Some("42501")));
            tx.rollback().await?;
        }
        for privilege in ["DELETE", "UPDATE(administrator_id)"] {
            let mut tx=admin.begin().await?;
            let query=format!("GRANT {privilege} ON aegaeon.organization_operator_grants TO \"{}\"",runtime.replace('"',"\"\""));
            sqlx::query(&query).execute(&mut *tx).await?;
            assert!(sqlx::query("SELECT aegaeon.subject_history_preflight($1)").bind(&runtime).execute(&mut *tx).await.is_err());
            tx.rollback().await?;
        }
        let mut tx=admin.begin().await?;
        sqlx::query("ALTER TABLE aegaeon.organization_operator_grants DROP CONSTRAINT organization_operator_grants_environment_id_domain_id_fkey")
            .execute(&mut *tx).await?;
        assert!(sqlx::query("SELECT aegaeon.subject_history_preflight($1)").bind(&runtime).execute(&mut *tx).await.is_err());
        tx.rollback().await?;
        crate::web::namespace_runtime::validate_database_inputs(
            &f.pool, f.env.environment_id, &f.env.issuer_url,
        ).await?;
        Ok(())
    }.await;
    admin.close().await;
    f.cleanup(result).await
}
