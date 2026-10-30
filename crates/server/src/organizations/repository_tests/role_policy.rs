use super::*;
use crate::organizations::operators::mutations::role_policy::{
    self as policy, Definition, RolePolicy,
};

async fn read(f: &Fixture) -> Result<RolePolicy, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let result = policy::read(&mut tx, f.organization.scope, f.env.team_id, f.actor.id).await;
    tx.rollback().await?;
    result
}
async fn change(
    f: &Fixture,
    key: &str,
    revision: i64,
    roles: &[Definition],
) -> Result<RolePolicy, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let result = policy::apply(
        &mut tx,
        f.organization.scope,
        f.env.team_id,
        &f.actor,
        key,
        revision,
        roles,
    )
    .await;
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}
fn input(value: &RolePolicy) -> Vec<Definition> {
    value
        .roles
        .iter()
        .map(|role| Definition {
            key: role.key.clone(),
            privileges: role.privileges.clone(),
            manages_members: role.manages_members,
            assignable_roles: role.assignable_roles.clone(),
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; actual role writes, manager boundary and outbox failure"]
async fn pg_organizations_role_policy_preserves_managers_versions_and_atomicity() -> TestResult {
    let f = Fixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let result=async {
        operators::principal(&f).await?;operators::grant(&f,serde_json::json!(["configure"])).await?;
        let before=read(&f).await?;
        let issued=f.access().await?;
        let mut tx=f.pool.begin().await?;
        let member=repository::membership(&mut tx,&f.organization,f.users[0]).await?.ok_or("member")?;
        let original_roles=repository::roles(&mut tx,f.organization.scope).await?;
        tx.rollback().await?;
        let mut remove_manager=input(&before);
        let role=remove_manager.iter_mut().find(|r|r.key=="admin").ok_or("admin")?;
        role.manages_members=false;role.assignable_roles.clear();
        assert!(matches!(change(&f,"last-manager",before.revision,&remove_manager).await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        assert_eq!(read(&f).await?,before);
        let mut different=input(&before);different.iter_mut().find(|r|r.key=="reader").ok_or("reader")?.privileges.push("documents.list".into());
        sqlx::raw_sql("CREATE FUNCTION aegaeon.role_policy_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture role outbox failure'; END $$; CREATE TRIGGER role_policy_fault BEFORE INSERT ON aegaeon.organization_authority_outbox FOR EACH ROW EXECUTE FUNCTION aegaeon.role_policy_fault()").execute(&admin).await?;
        assert!(matches!(change(&f,"reader",before.revision,&different).await,Err(RepositoryError::Storage(_))));
        assert_eq!(read(&f).await?,before);
        sqlx::raw_sql("DROP TRIGGER role_policy_fault ON aegaeon.organization_authority_outbox; DROP FUNCTION aegaeon.role_policy_fault()").execute(&admin).await?;
        let updated=change(&f,"reader",before.revision,&different).await?;
        let mut tx=f.pool.begin().await?;
        let roles=repository::roles(&mut tx,f.organization.scope).await?;tx.rollback().await?;
        assert_eq!(roles["admin"].version,original_roles["admin"].version);
        assert_eq!(roles["reader"].version,original_roles["reader"].version+1);
        assert!(issued.is_current(&f.organization,&member,&roles,100),"an unused role edit must not revoke this organization's grant");
        let mut expanded=input(&updated);expanded.iter_mut().find(|r|r.key=="admin").ok_or("admin")?.privileges.push("documents.read".into());
        change(&f,"admin",updated.revision,&expanded).await?;
        let mut tx=f.pool.begin().await?;let roles=repository::roles(&mut tx,f.organization.scope).await?;tx.rollback().await?;
        assert!(!issued.is_current(&f.organization,&member,&roles,100),"changed role version must revoke issued authority");
        let ceiling=AuthorizationCeiling {version:1,binding:issued.binding.clone(),expires_at:1000,audiences:std::collections::BTreeMap::from([("management-api".into(),issued.privileges.clone())]),memberships:std::collections::BTreeMap::from([(f.organization.id,AuthorizationCeiling::capture_membership(&f.organization,&member,&original_roles)?)]),};
        let request=AccessRequest {detail_type:ORGANIZATION_ACCESS_TYPE.into(),
            admin_access_grant_id: None,identifier:f.organization.external_id.clone(),privileges:None};
        assert_eq!(AccessDecision::authorize(AccessInput {ceiling:&ceiling,authenticated:&ceiling.binding,request:&request,audience:"management-api",current_client_privileges:&issued.privileges,organization:&f.organization,member:&member,definitions:&roles,parent_expires_at:1000,now:100}),Err(AuthorityError::ReauthorizationRequired));
        // Global security suspension remains possible even for every manager.
        sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE environment_id=$1").bind(f.env.environment_id).execute(&f.pool).await?;
        let mut tx=f.pool.begin().await?;
        assert!(matches!(repository::require_active_identity(&mut tx,f.organization.scope,f.users[0],None).await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        tx.rollback().await?;
        Ok(())
    }.await;
    admin.close().await;
    f.cleanup(result).await
}
