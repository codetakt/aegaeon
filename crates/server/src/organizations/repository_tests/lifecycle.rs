use super::*;
use crate::organizations::operators::mutations::{lifecycle, targets::DomainConfiguration};

async fn apply(
    f: &Fixture,
    key: &str,
    revision: i64,
    enabled: bool,
) -> Result<DomainConfiguration, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let result = lifecycle::apply(
        &mut tx,
        f.organization.scope,
        f.env.team_id,
        &f.actor,
        key,
        revision,
        enabled,
    )
    .await?;
    tx.commit().await?;
    Ok(result)
}

async fn configured(f: &Fixture) -> TestResult {
    clients::configured(f).await?;
    sqlx::query("UPDATE aegaeon.authorization_domains SET enabled=false WHERE id=$1")
        .bind(f.organization.scope.domain_id)
        .execute(&f.pool)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_domain_lifecycle_current_client_revision_and_retry_authority(
) -> TestResult {
    let f = Fixture::new().await?;
    let result=async {
        configured(&f).await?;
        assert!(matches!(apply(&f,"no-client",1,true).await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        let id=clients::registration(&f,"lifecycle").await?;
        clients::apply(&f,"client",&clients::create(id,1)).await?;
        sqlx::query("UPDATE aegaeon.clients SET dpop_bound_access_tokens=false WHERE id=$1").bind(id).execute(&f.pool).await?;
        assert!(matches!(apply(&f,"unsafe-client",2,true).await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        sqlx::query("UPDATE aegaeon.clients SET dpop_bound_access_tokens=true WHERE id=$1").bind(id).execute(&f.pool).await?;
        let enabled=apply(&f,"enable",2,true).await?;
        assert!(enabled.enabled);
        assert_eq!(enabled.revision,3);
        assert!(matches!(apply(&f,"same-state",3,true).await,Err(RepositoryError::Authority(AuthorityError::Conflict))));
        assert!(matches!(apply(&f,"stale",2,false).await,Err(RepositoryError::Authority(AuthorityError::PreconditionFailed))));
        let disabled=apply(&f,"disable",3,false).await?;
        assert!(!disabled.enabled);
        assert_eq!(disabled.revision,4);
        assert_eq!(apply(&f,"enable",2,true).await?,enabled);
        let current:bool=sqlx::query_scalar("SELECT enabled FROM aegaeon.authorization_domains WHERE id=$1").bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;
        assert!(!current,"replay must not re-enable the domain");
        let reenabled=apply(&f,"enable-again",4,true).await?;
        assert_eq!(reenabled.revision,5);
        assert_ne!(reenabled.revision,enabled.revision);
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE administrator_id=$1").bind(f.actor.id).execute(&f.pool).await?;
        assert!(matches!(apply(&f,"enable",2,true).await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_domain_disable_reserves_revision_and_receipt_after_client_deletion(
) -> TestResult {
    let f = Fixture::new().await?;
    let result=async {
        configured(&f).await?;
        let id=clients::registration(&f,"disable-reserve").await?;
        clients::apply(&f,"client",&clients::create(id,1)).await?;
        apply(&f,"enable",2,true).await?;
        sqlx::query("DELETE FROM aegaeon.clients WHERE id=$1").bind(id).execute(&f.pool).await?;
        sqlx::query("UPDATE aegaeon.authorization_domains SET revision=$2 WHERE id=$1").bind(f.organization.scope.domain_id).bind(i64::MAX-1).execute(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result) SELECT $1,$2,$3,'operator','fixture',$4,'domain.fixture',n::text,decode(repeat('ab',32),'hex'),'{}' FROM generate_series(1,9998) n")
            .bind(f.env.environment_id).bind(f.organization.scope.domain_id).bind(f.actor.id).bind(Uuid::nil()).execute(&f.pool).await?;
        let disabled=apply(&f,"reserved",i64::MAX-1,false).await?;
        assert_eq!(disabled.revision,i64::MAX);
        assert!(!disabled.enabled);
        assert!(matches!(apply(&f,"reenable",i64::MAX,true).await,Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        assert_eq!(apply(&f,"reserved",i64::MAX-1,false).await?,disabled);
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and owned fault injection"]
async fn pg_organizations_domain_transition_serializes_and_audit_failure_rolls_back() -> TestResult
{
    let f = Fixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let result=async {
        clients::configured(&f).await?;
        sqlx::query("CREATE FUNCTION aegaeon.organization_domain_fault() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''domain audit fault''; END'").execute(&admin).await?;
        sqlx::query("CREATE TRIGGER organization_domain_fault BEFORE INSERT ON aegaeon.organization_authority_outbox FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_domain_fault()").execute(&admin).await?;
        assert!(matches!(apply(&f,"disable",1,false).await,Err(RepositoryError::Storage(sqlx::Error::Database(ref e))) if e.code().as_deref()==Some("P0001")));
        sqlx::query("DROP TRIGGER organization_domain_fault ON aegaeon.organization_authority_outbox").execute(&admin).await?;
        sqlx::query("DROP FUNCTION aegaeon.organization_domain_fault()").execute(&admin).await?;
        let mut first=f.pool.begin().await?;
        let disabled=lifecycle::apply(&mut first,f.organization.scope,f.env.team_id,&f.actor,"disable",1,false).await?;
        let mut concurrent=f.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *concurrent).await?;
        assert!(matches!(lifecycle::apply(&mut concurrent,f.organization.scope,f.env.team_id,&f.actor,"disable",1,false).await,Err(RepositoryError::Storage(sqlx::Error::Database(ref e))) if e.code().as_deref()==Some("55P03")));
        concurrent.rollback().await?;
        first.commit().await?;
        assert_eq!(apply(&f,"disable",1,false).await?,disabled);
        Ok(())
    }.await;
    admin.close().await;
    f.cleanup(result).await
}
