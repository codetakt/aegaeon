use super::*;
use crate::organizations::{commands, repository, MembershipState, OrganizationState};
use uuid::Uuid;

async fn status(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    token: &str,
) -> TestResult<StatusCode> {
    let signed = proof(state, key, token, "GET", json!({}))?;
    Ok(get(
        state,
        Method::GET,
        PATH,
        Some(&format!("DPoP {token}")),
        Some(&signed),
        "",
    )
    .await?
    .0)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_administrator_recovery_never_restores_old_root() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&f).await?;
    let result=async {
        let key=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (_,old)=issue(&f,&state,&key,PRIVILEGE).await?;
        assert_eq!(status(&state,&key,&old).await?,StatusCode::OK);
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"configure\",\"provision\"]',revision=revision+1 WHERE domain_id=$1").bind(f.organization.scope.domain_id).execute(&f.pool).await?;
        sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE id=$1").bind(f.users[0]).execute(&f.pool).await?;
        let mut tx=f.pool.begin().await?;
        let command=commands::Command::PrepareAdministratorRecovery {organization_id:f.organization.id,expected_revision:f.organization.revision};
        let commands::CommandResult::Organization(recovering)=commands::apply_operator_command(&mut tx,f.organization.scope,f.env.team_id,&f.actor,"recover",&command).await? else {return Err("organization expected".into())};
        tx.commit().await?;
        assert_eq!(status(&state,&key,&old).await?,StatusCode::UNAUTHORIZED);
        // Native invitation acceptance is exercised separately. This fixture
        // supplies its final new administrator state to isolate token recovery.
        let replacement=Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')").bind(replacement).bind(f.env.environment_id).bind(replacement.to_string()).execute(&f.pool).await?;
        let mut tx=f.pool.begin().await?;
        repository::update_membership(&mut tx,f.organization.scope,f.organization.id,
            repository::MembershipUpdate {user_id:replacement,expected_revision:0,state:MembershipState::Active,roles:std::collections::BTreeSet::from(["admin".into()])},&f.actor).await?;
        repository::transition_organization(&mut tx,f.organization.scope,f.organization.id,recovering.revision,OrganizationState::Active,&f.actor).await?;tx.commit().await?;
        assert_eq!(status(&state,&key,&old).await?,StatusCode::UNAUTHORIZED,"reactivation cannot restore old original generation");
        let (_,fresh)=issue(&f,&state,&key,PRIVILEGE).await?;
        assert_eq!(status(&state,&key,&fresh).await?,StatusCode::OK);
        Ok(())
    }.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
