use super::*;
use serde_json::{json, Value};

async fn member_version(f: &Fixture, user: Uuid) -> Result<Value, sqlx::Error> {
    sqlx::query_scalar("SELECT jsonb_build_object('state',state,'revision',revision,'generation',grant_generation,'incarnation',incarnation) FROM aegaeon.organization_memberships WHERE organization_id=$1 AND end_user_id=$2")
        .bind(f.organization.id).bind(user).fetch_one(&f.pool).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_audit_transitions_record_actual_before_after_and_captured_basis(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        operators::principal(&f).await?;
        operators::grant(&f,json!(["provision"])).await?;
        let mut tx = f.pool.begin().await?;
        let created = commands::apply_operator_command(&mut tx,f.organization.scope,f.env.team_id,&f.actor,"audit-create",&commands::Command::Create { external_id:"audit-version".into() }).await?;
        tx.commit().await?;
        let commands::CommandResult::Organization(org) = created else { return Err("organization result".into()); };
        let event: Value = sqlx::query_scalar("SELECT data FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.created'").bind(org.id).fetch_one(&f.pool).await?;
        assert!(event["before"].is_null());
        assert_eq!(event["after"],json!({"state":"provisioning","revision":1,"generation":1}));
        assert_eq!(event["authorityBasis"]["kind"],"domain_operator");
        assert_eq!(event["authorityBasis"]["capability"],"provision");
        assert_eq!(event["authorityBasis"]["revision"],1);
        let mut tx = f.pool.begin().await?;
        commands::apply_operator_command(&mut tx,org.scope,f.env.team_id,&f.actor,"audit-delete",&commands::Command::SetState { organization_id:org.id, expected_revision:1,state:OrganizationState::Deleted }).await?;
        tx.commit().await?;
        let event: Value = sqlx::query_scalar("SELECT data FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.state_changed'").bind(org.id).fetch_one(&f.pool).await?;
        assert_eq!(event["before"],json!({"state":"provisioning","revision":1,"generation":1}));
        let persisted:Value = sqlx::query_scalar("SELECT jsonb_build_object('state',state,'revision',revision,'generation',grant_generation) FROM aegaeon.application_organizations WHERE id=$1").bind(org.id).fetch_one(&f.pool).await?;
        assert_eq!(persisted,json!({"state":"deleted","revision":2,"generation":1}));
        assert_eq!(event["after"],persisted);
        let before = member_version(&f,f.users[1]).await?;
        let access = f.access().await?;
        f.delegate(&access,"audit-member").await?;
        let after = member_version(&f,f.users[1]).await?;
        let event: Value = sqlx::query_scalar("SELECT data FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.membership_changed' AND actor_kind='member'").bind(f.organization.id).fetch_one(&f.pool).await?;
        assert_eq!(event["before"],before);
        assert_eq!(event["after"],after);
        assert_eq!(event["authorityBasis"]["kind"],"delegated_membership");
        assert_eq!(event["authorityBasis"]["rootId"],access.binding.root_id);
        let bytes = event.to_string();
        assert!(!bytes.contains(&access.binding.dpop_jkt),"public proof binding is unnecessary in this audit record");
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_audit_transitions_self_revocation_retains_prechange_authority(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        operators::principal(&f).await?;
        operators::grant(&f,json!(["configure"])).await?;
        let id: Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.organization_operator_grants WHERE domain_id=$1 AND administrator_id=$2")
            .bind(f.organization.scope.domain_id).bind(f.actor.id).fetch_one(&f.pool).await?;
        let mut tx = f.pool.begin().await?;
        let result = crate::organizations::operators::mutations::apply_grant_command(&mut tx,f.organization.scope,f.env.team_id,&f.actor,"revoke-self",&crate::organizations::operators::mutations::GrantCommand::Revoke { id,expected_revision:1 }).await?;
        assert!(!result.active);
        tx.commit().await?;
        let event: Value = sqlx::query_scalar("SELECT data FROM aegaeon.organization_authority_events WHERE domain_id=$1 AND event_type='domain.operator.revoke'")
            .bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;
        assert_eq!(event["before"]["revision"],1);
        assert_eq!(event["after"]["revision"],2);
        assert_eq!(event["authorityBasis"]["revision"],1,"audit captures the authorization that passed before revoking itself");
        assert_eq!(event["authorityBasis"]["grantId"],id.to_string());
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual JSONB rendering and transaction rollback"]
async fn pg_organizations_audit_transitions_byte_budget_survives_jsonb_and_refusal_rolls_back(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        operators::principal(&f).await?;
        operators::grant(&f,json!(["export"])).await?;
        let mut data = json!({"values":vec![u64::MAX;1000],"text":""});
        let used = serde_json::to_vec(&data)?.len();
        data["text"] = "x".repeat(crate::organizations::audit::retention::MAX_DATA_BYTES-used).into();
        assert_eq!(serde_json::to_vec(&data)?.len(),crate::organizations::audit::retention::MAX_DATA_BYTES);
        let mut tx = f.pool.begin().await?;
        repository::event(&mut tx,&f.organization,&f.actor,"organization.fixture_boundary",data).await?;
        tx.commit().await?;
        let bytes:i32 = sqlx::query_scalar("SELECT octet_length(data::text) FROM aegaeon.organization_authority_events WHERE domain_id=$1 AND event_type='organization.fixture_boundary'")
            .bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;
        assert!(bytes < 60*1024);
        let mut tx = f.pool.begin().await?;
        let page=crate::organizations::audit::read(&mut tx,f.organization.scope,f.env.team_id,f.actor.id,100,None).await?;
        assert!(serde_json::to_vec(&page)?.len()<64*1024);
        tx.rollback().await?;
        let mut tx = f.pool.begin().await?;
        let before=repository::lock_organization(&mut tx,f.organization.scope,f.organization.id).await?;
        // Owned fault: force writer-budget refusal after the native state UPDATE.
        let actor=f.actor.with_basis(json!({"value":"x".repeat(crate::organizations::audit::retention::MAX_DATA_BYTES)}));
        let rejected=repository::transition_organization(&mut tx,before.scope,before.id,before.revision,OrganizationState::Suspended,&actor).await;
        assert!(matches!(rejected,Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        tx.rollback().await?;
        let mut tx = f.pool.begin().await?;
        assert_eq!(repository::lock_organization(&mut tx,before.scope,before.id).await?,before);
        tx.rollback().await?;
        Ok(())
    }.await;
    f.cleanup(result).await
}
