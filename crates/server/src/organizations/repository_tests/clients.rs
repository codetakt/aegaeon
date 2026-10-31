use super::*;
use crate::organizations::operators::mutations::clients::{
    self, ClientBinding, ClientCommand, ClientTarget,
};

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and owned catalog fault injection"]
async fn pg_organizations_client_retained_quota_and_catalog_authority() -> TestResult {
    let f = Fixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let result = async {
        configured(&f).await?;
        sqlx::query("INSERT INTO aegaeon.organization_client_bindings(id,environment_id,domain_id,client_registration_id,client_identifier,targets) SELECT gen_random_uuid(),$1,$2,gen_random_uuid(),'retained-'||n,$3 FROM generate_series(1,63) n")
            .bind(f.env.environment_id).bind(f.organization.scope.domain_id).bind(serde_json::to_value(targets())?).execute(&f.pool).await?;
        let id = registration(&f,"last-slot").await?;
        let last = apply(&f,"last-slot",&create(id,1)).await?;
        let overflow = registration(&f,"overflow").await?;
        assert!(matches!(apply(&f,"overflow",&create(overflow,2)).await,Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        apply(&f,"revoke",&ClientCommand::Revoke{id:last.id,expected_revision:1}).await?;
        assert!(matches!(apply(&f,"still-full",&create(overflow,2)).await,Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        let runtime:String = sqlx::query_scalar("SELECT current_user::text").fetch_one(&f.pool).await?;
        for query in ["DELETE FROM aegaeon.organization_client_bindings WHERE id=$1","UPDATE aegaeon.organization_client_bindings SET client_registration_id=gen_random_uuid() WHERE id=$1"] {
            let error = sqlx::query(query).bind(last.id).execute(&f.pool).await.unwrap_err();
            assert!(matches!(error,sqlx::Error::Database(ref e) if e.code().as_deref()==Some("42501")));
        }
        for privilege in ["DELETE","UPDATE(client_registration_id)"] {
            let mut tx=admin.begin().await?;
            sqlx::query(&format!("GRANT {privilege} ON aegaeon.organization_client_bindings TO \"{}\"",runtime.replace('"',"\"\""))).execute(&mut *tx).await?;
            assert!(sqlx::query("SELECT aegaeon.subject_history_preflight($1)").bind(&runtime).execute(&mut *tx).await.is_err());
            tx.rollback().await?;
        }
        crate::web::namespace_runtime::validate_database_inputs(&f.pool,f.env.environment_id,&f.env.issuer_url).await?;
        Ok(())
    }.await;
    admin.close().await;
    f.cleanup(result).await
}

pub(super) async fn configured(f: &Fixture) -> TestResult {
    operators::principal(f).await?;
    operators::grant(f, serde_json::json!(["configure"])).await
}

pub(super) async fn registration(f: &Fixture, name: &str) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.clients(id,environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,dpop_bound_access_tokens) SELECT $1,id,active_configuration_version_id,$2,'organization fixture','CONFIDENTIAL',ARRAY['https://example.test/cb'],ARRAY['authorization_code','urn:ietf:params:oauth:grant-type:token-exchange'],ARRAY['openid'],'client_secret_basic',true FROM aegaeon.environments WHERE id=$3")
        .bind(id).bind(name).bind(f.env.environment_id).execute(&f.pool).await?;
    Ok(id)
}

fn targets() -> Vec<ClientTarget> {
    vec![ClientTarget {
        audience: "management-api".into(),
        privileges: vec!["documents.read".into()],
    }]
}

pub(super) fn create(id: Uuid, expected_revision: i64) -> ClientCommand {
    ClientCommand::Create {
        client_registration_id: id,
        expected_revision,
        active: true,
        targets: targets(),
    }
}

pub(super) async fn apply(
    f: &Fixture,
    key: &str,
    command: &ClientCommand,
) -> Result<ClientBinding, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let value = clients::apply(
        &mut tx,
        f.organization.scope,
        f.env.team_id,
        &f.actor,
        key,
        command,
    )
    .await?;
    tx.commit().await?;
    Ok(value)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_client_binding_identity_replay_revoke_and_reregistration() -> TestResult {
    let f = Fixture::new().await?;
    let result=async {
        configured(&f).await?;
        let id=registration(&f,"exact.Client-学校").await?;
        let command=create(id,1);
        let first=apply(&f,"create",&command).await?;
        assert_eq!(first.client_registration_id,id);
        assert_eq!(first.client_identifier,"exact.Client-学校");
        assert!(first.active);
        assert_eq!(apply(&f,"create",&command).await?,first);
        assert!(matches!(apply(&f,"stale",&command).await,Err(RepositoryError::Authority(AuthorityError::PreconditionFailed))));
        assert!(matches!(apply(&f,"duplicate",&create(id,2)).await,Err(RepositoryError::Authority(AuthorityError::Conflict))));
        sqlx::query("DELETE FROM aegaeon.clients WHERE id=$1").bind(id).execute(&f.pool).await?;
        let replacement=registration(&f,"exact.Client-学校").await?;
        let replacement_binding=apply(&f,"replacement",&create(replacement,2)).await?;
        assert_ne!(first.id,replacement_binding.id);
        assert_ne!(first.client_registration_id,replacement_binding.client_registration_id);
        let revoked=apply(&f,"revoke",&ClientCommand::Revoke{id:first.id,expected_revision:1}).await?;
        assert!(!revoked.active);
        assert_eq!(revoked.targets,first.targets);
        assert!(matches!(apply(&f,"reactivate-deleted",&ClientCommand::Update{id:first.id,expected_revision:2,active:true,targets:targets()}).await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        let mut tx=f.pool.begin().await?;
        assert_eq!(clients::list(&mut tx,f.organization.scope,f.env.team_id,f.actor.id).await?.len(),2);
        tx.rollback().await?;
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE administrator_id=$1").bind(f.actor.id).execute(&f.pool).await?;
        assert!(matches!(apply(&f,"create",&command).await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_client_activation_checks_current_policy_scope_and_exact_targets(
) -> TestResult {
    let f = Fixture::new().await?;
    let foreign = Fixture::new().await?;
    let result = async {
        configured(&f).await?;
        let id = registration(&f, "policy").await?;
        let other = registration(&foreign, "policy").await?;
        assert!(matches!(
            apply(&f, "foreign", &create(other, 1)).await,
            Err(RepositoryError::Authority(AuthorityError::Forbidden))
        ));
        for update in [
            "dpop_bound_access_tokens=false",
            "status='DELETED'",
            "deleted_at=now()",
            "client_type='PUBLIC',token_endpoint_authentication_method='none'",
            "allowed_grant_types=ARRAY['authorization_code']",
        ] {
            let mut tx = f.pool.begin().await?;
            sqlx::query(&format!("UPDATE aegaeon.clients SET {update} WHERE id=$1"))
                .bind(id)
                .execute(&mut *tx)
                .await?;
            assert!(
                matches!(
                    clients::apply(
                        &mut tx,
                        f.organization.scope,
                        f.env.team_id,
                        &f.actor,
                        "bad-policy",
                        &create(id, 1)
                    )
                    .await,
                    Err(RepositoryError::Authority(AuthorityError::Forbidden))
                ),
                "{update}"
            );
            tx.rollback().await?;
        }
        for values in [
            vec![],
            vec![ClientTarget {
                audience: "Management-api".into(),
                privileges: vec!["documents.read".into()],
            }],
            vec![ClientTarget {
                audience: "management-api".into(),
                privileges: vec![],
            }],
            vec![targets()[0].clone(), targets()[0].clone()],
            vec![ClientTarget {
                audience: "management-api".into(),
                privileges: vec!["documents.read".into(), "documents.read".into()],
            }],
        ] {
            assert!(apply(
                &f,
                "invalid-target",
                &ClientCommand::Create {
                    client_registration_id: id,
                    expected_revision: 1,
                    active: true,
                    targets: values
                }
            )
            .await
            .is_err());
        }
        let first = apply(&f, "valid", &create(id, 1)).await?;
        let second = apply(
            &f,
            "update",
            &ClientCommand::Update {
                id: first.id,
                expected_revision: 1,
                active: false,
                targets: targets(),
            },
        )
        .await?;
        assert_eq!(second.revision, 2);
        assert!(!second.active);
        assert!(matches!(
            apply(
                &f,
                "stale",
                &ClientCommand::Update {
                    id: first.id,
                    expected_revision: 1,
                    active: true,
                    targets: targets()
                }
            )
            .await,
            Err(RepositoryError::Authority(
                AuthorityError::PreconditionFailed
            ))
        ));
        Ok(())
    }
    .await;
    foreign.cleanup(Ok(())).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and owned fault injection"]
async fn pg_organizations_client_rollback_race_and_reserved_revocation() -> TestResult {
    let f = Fixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let result=async {
        configured(&f).await?;
        let id=registration(&f,"reserve").await?;
        // Fault is installed by setup authority; the mutation still uses runtime privileges.
        sqlx::query("CREATE FUNCTION aegaeon.organization_client_fault() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''client audit fault''; END'").execute(&admin).await?;
        sqlx::query("CREATE TRIGGER organization_client_fault BEFORE INSERT ON aegaeon.organization_authority_outbox FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_client_fault()").execute(&admin).await?;
        assert!(matches!(apply(&f,"create",&create(id,1)).await,Err(RepositoryError::Storage(sqlx::Error::Database(ref e))) if e.code().as_deref()==Some("P0001")));
        sqlx::query("DROP TRIGGER organization_client_fault ON aegaeon.organization_authority_outbox").execute(&admin).await?;
        sqlx::query("DROP FUNCTION aegaeon.organization_client_fault()").execute(&admin).await?;
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_client_bindings WHERE domain_id=$1").bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;
        assert_eq!(count,0);
        let mut tx=f.pool.begin().await?;
        let first=clients::apply(&mut tx,f.organization.scope,f.env.team_id,&f.actor,"create",&create(id,1)).await?;
        let mut competing=f.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *competing).await?;
        assert!(matches!(clients::apply(&mut competing,f.organization.scope,f.env.team_id,&f.actor,"raced",&create(id,1)).await,Err(RepositoryError::Storage(sqlx::Error::Database(ref e))) if e.code().as_deref()==Some("55P03")));
        competing.rollback().await?;
        tx.commit().await?;
        sqlx::query("UPDATE aegaeon.organization_client_bindings SET revision=$2 WHERE id=$1").bind(first.id).bind(i64::MAX-1).execute(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result) SELECT $1,$2,$3,'operator','fixture',$4,'domain.fixture',n::text,decode(repeat('ab',32),'hex'),'{}' FROM generate_series(1,9999) n")
            .bind(f.env.environment_id).bind(f.organization.scope.domain_id).bind(f.actor.id).bind(Uuid::nil()).execute(&f.pool).await?;
        assert!(matches!(apply(&f,"full",&ClientCommand::Update{id:first.id,expected_revision:i64::MAX-1,active:true,targets:targets()}).await,Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        sqlx::query("DELETE FROM aegaeon.clients WHERE id=$1").bind(id).execute(&f.pool).await?;
        let revoked=apply(&f,"reserved",&ClientCommand::Revoke{id:first.id,expected_revision:i64::MAX-1}).await?;
        assert_eq!(revoked.revision,i64::MAX);
        assert!(!revoked.active);
        assert_eq!(apply(&f,"reserved",&ClientCommand::Revoke{id:first.id,expected_revision:i64::MAX-1}).await?,revoked);
        Ok(())
    }.await;
    admin.close().await;
    f.cleanup(result).await
}
