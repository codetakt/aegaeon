use super::*;
use crate::organizations::operators::mutations::targets::{
    self,
    recipients::{self, ConfigureRecipients},
};

fn replace(revision: i64, ids: Vec<Uuid>) -> ConfigureRecipients {
    ConfigureRecipients {
        expected_revision: revision,
        audience: "management-api".into(),
        registrations: Some(ids),
    }
}
async fn apply(
    f: &Fixture,
    key: &str,
    command: &ConfigureRecipients,
) -> Result<targets::DomainConfiguration, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let result = recipients::apply(
        &mut tx,
        f.organization.scope,
        f.env.team_id,
        &f.actor,
        key,
        command,
    )
    .await?;
    tx.commit().await?;
    Ok(result)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_recipients_exact_registration_replay_and_revocation() -> TestResult {
    let f = Fixture::new().await?;
    let other = Fixture::new().await?;
    let result=async {
        clients::configured(&f).await?;
        let id=clients::registration(&f,"rs.学校").await?;
        let foreign=clients::registration(&other,"rs.学校").await?;
        assert!(matches!(apply(&f,"foreign",&replace(1,vec![foreign])).await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        let mut wrong=replace(1,vec![id]);wrong.audience="Management-api".into();
        assert!(matches!(apply(&f,"wrong-target",&wrong).await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        let first=apply(&f,"first",&replace(1,vec![id])).await?;
        assert_eq!(first.revision,2);
        assert_eq!(first.targets[0].introspection_clients[0].client_identifier,"rs.学校");
        assert_eq!(first.targets[0].introspection_clients[0].client_registration_id,id);
        assert!(matches!(apply(&f,"stale",&replace(1,vec![id])).await,Err(RepositoryError::Authority(AuthorityError::PreconditionFailed))));
        assert!(matches!(apply(&f,"same",&replace(2,vec![id])).await,Err(RepositoryError::Authority(AuthorityError::Conflict))));
        sqlx::query("DELETE FROM aegaeon.clients WHERE id=$1").bind(id).execute(&f.pool).await?;
        let replacement=clients::registration(&f,"rs.学校").await?;
        let mut tx=f.pool.begin().await?;
        assert!(recipients::current(&mut tx,f.organization.scope,id).await.is_err());
        assert_ne!(recipients::current(&mut tx,f.organization.scope,replacement).await?,first.targets[0].introspection_clients[0]);
        tx.rollback().await?;
        let revoked=apply(&f,"revoke",&ConfigureRecipients{registrations:None,..replace(2,vec![])}).await?;
        assert!(revoked.targets[0].introspection_clients.is_empty());
        assert_eq!(apply(&f,"first",&replace(1,vec![id])).await?,first);
        let stored:serde_json::Value=sqlx::query_scalar("SELECT introspection_clients FROM aegaeon.authorization_domain_targets WHERE environment_id=$1")
            .bind(f.env.environment_id).fetch_one(&f.pool).await?;
        assert_eq!(stored,serde_json::json!([]),"replay cannot restore recipients");
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE administrator_id=$1").bind(f.actor.id).execute(&f.pool).await?;
        assert!(matches!(apply(&f,"first",&replace(1,vec![id])).await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        Ok(())
    }.await;
    other.cleanup(Ok(())).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_recipients_confidential_current_and_bounded() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        clients::configured(&f).await?;
        let id = clients::registration(&f, "rs").await?;
        // Keep the database's client-type/auth-method invariant valid while
        // exercising the application eligibility guard.
        for settings in ["client_type='PUBLIC',token_endpoint_authentication_method='none'", "deleted_at=now()", "status='DELETED'"] {
            sqlx::query(&format!("UPDATE aegaeon.clients SET {settings} WHERE id=$1"))
                .bind(id).execute(&f.pool).await?;
            assert!(matches!(apply(&f, "ineligible", &replace(1, vec![id])).await,
                Err(RepositoryError::Authority(AuthorityError::Forbidden))));
            sqlx::query("UPDATE aegaeon.clients SET client_type='CONFIDENTIAL',token_endpoint_authentication_method='client_secret_basic',deleted_at=NULL,status='ACTIVE' WHERE id=$1")
                .bind(id).execute(&f.pool).await?;
        }
        for ids in [vec![], vec![id, id], vec![Uuid::nil()], vec![id; 9]] {
            assert!(matches!(
                apply(&f, "bounds", &replace(1, ids)).await,
                Err(RepositoryError::Authority(AuthorityError::Invalid))
            ));
        }
        let mut ids = vec![id];
        for i in 1..8 {
            ids.push(clients::registration(&f, &format!("rs-{i}")).await?);
        }
        let eight = apply(&f, "eight", &replace(1, ids.clone())).await?;
        assert_eq!(eight.targets[0].introspection_clients.len(), 8);
        ids.push(clients::registration(&f, "ninth").await?);
        assert!(matches!(
            apply(&f, "nine", &replace(2, ids)).await,
            Err(RepositoryError::Authority(AuthorityError::Invalid))
        ));
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and owned audit fault"]
async fn pg_organizations_recipients_atomic_audit_and_reserved_revocation() -> TestResult {
    let f = Fixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let result=async {
        clients::configured(&f).await?;
        let id=clients::registration(&f,"rs").await?;
        let mut tx=admin.begin().await?;
        sqlx::query("CREATE FUNCTION pg_temp.recipient_fault() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''recipient audit fault''; END'").execute(&mut *tx).await?;
        sqlx::query("CREATE TRIGGER recipient_fault BEFORE INSERT ON aegaeon.organization_authority_outbox FOR EACH ROW EXECUTE FUNCTION pg_temp.recipient_fault()").execute(&mut *tx).await?;
        assert!(matches!(recipients::apply(&mut tx,f.organization.scope,f.env.team_id,&f.actor,"fault",&replace(1,vec![id])).await,Err(RepositoryError::Storage(sqlx::Error::Database(ref e))) if e.code().as_deref()==Some("P0001")));
        tx.rollback().await?;
        let first=apply(&f,"first",&replace(1,vec![id])).await?;
        assert_eq!(first.revision,2,"failed transaction preserved revision");
        sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result) SELECT $1,$2,$3,'operator','fixture',$4,'domain.fixture',n::text,decode(repeat('00',32),'hex'),'{}'::jsonb FROM generate_series(1,9999) n")
            .bind(f.env.environment_id).bind(f.organization.scope.domain_id).bind(f.actor.id).bind(Uuid::nil()).execute(&f.pool).await?;
        let extra=clients::registration(&f,"extra").await?;
        assert!(matches!(apply(&f,"full",&replace(2,vec![extra])).await,Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        let revoke=ConfigureRecipients{registrations:None,..replace(2,vec![])};
        let revoked=apply(&f,"revoke",&revoke).await?;
        assert_eq!(revoked.revision,3);
        assert!(revoked.targets[0].introspection_clients.is_empty());
        assert_eq!(apply(&f,"revoke",&revoke).await?,revoked);
        assert!(matches!(apply(&f,"empty-revoke",&ConfigureRecipients{registrations:None,..replace(3,vec![])}).await,Err(RepositoryError::Authority(AuthorityError::Conflict))));
        Ok(())
    }.await;
    admin.close().await;
    f.cleanup(result).await
}
