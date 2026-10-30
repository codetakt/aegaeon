use super::*;
use crate::organizations::operators::{mutations::*, Capability};

async fn configured(f: &Fixture) -> TestResult {
    operators::principal(f).await?;
    operators::grant(f, serde_json::json!(["configure", "provision"])).await
}

async fn target(f: &Fixture) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.administrators(id,email,password_hash,kind,status) VALUES ($1,$2,'unused-fixture','HUMAN','ACTIVE')")
        .bind(id).bind(format!("{id}@operator.example")).execute(&f.pool).await?;
    sqlx::query("INSERT INTO aegaeon.team_memberships(team_id,administrator_id,role) VALUES ($1,$2,'READONLY')")
        .bind(f.env.team_id).bind(id).execute(&f.pool).await?;
    Ok(id)
}

async fn apply(
    f: &Fixture,
    key: &str,
    command: &GrantCommand,
) -> Result<OperatorGrant, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let result = apply_grant_command(
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
async fn pg_organizations_operator_mutations_replay_cas_and_revocation() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        configured(&f).await?;
        let command = GrantCommand::Create { administrator_id: target(&f).await?, active: true, capabilities: vec![Capability::Reconcile] };
        let created = apply(&f, "create", &command).await?;
        assert_eq!(apply(&f, "create", &command).await?, created);
        assert!(matches!(apply(&f, "new-key", &command).await, Err(RepositoryError::Authority(AuthorityError::Conflict))));
        let update = GrantCommand::Update { id: created.id, expected_revision: 1, active: false, capabilities: vec![Capability::Reconcile] };
        let revoked = apply(&f, "revoke", &update).await?;
        assert_eq!(revoked.id, created.id);
        assert_eq!(revoked.revision, 2);
        assert!(!revoked.active);
        assert_eq!(apply(&f, "revoke", &update).await?, revoked);
        assert!(matches!(apply(&f, "stale", &update).await, Err(RepositoryError::Authority(AuthorityError::PreconditionFailed))));
        let changed = GrantCommand::Update { id: created.id, expected_revision: 2, active: true, capabilities: vec![Capability::Export] };
        assert!(matches!(apply(&f, "revoke", &changed).await, Err(RepositoryError::Authority(AuthorityError::Conflict))));
        let active = apply(&f, "reactivate", &changed).await?;
        assert_eq!(active.id, created.id);
        assert_eq!(active.revision, 3);
        assert_eq!(active.capabilities, BTreeSet::from([Capability::Export]));
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events e JOIN aegaeon.organization_authority_outbox o ON o.event_id=e.id WHERE e.domain_id=$1 AND e.organization_id IS NULL")
            .bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;
        assert_eq!(events, 3);
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE administrator_id=$1").bind(f.actor.id).execute(&f.pool).await?;
        assert!(apply(&f, "create", &command).await.is_err());
        assert!(apply(&f, "revoke", &update).await.is_err());
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_operator_cannot_provision_members_or_replay_without_grant() -> TestResult
{
    let f = Fixture::new().await?;
    let result = async {
        configured(&f).await?;
        let create = commands::Command::Create { external_id: "provisioned/exact/学校".into() };
        let mut tx = f.pool.begin().await?;
        let first = commands::apply_operator_command(&mut tx, f.organization.scope, f.env.team_id, &f.actor, "provision", &create).await?;
        tx.commit().await?;
        let member = commands::Command::SetMember { organization_id: f.organization.id, update: MembershipUpdate { user_id: f.users[1], expected_revision: 1, state: MembershipState::Removed, roles: BTreeSet::new() } };
        let mut tx = f.pool.begin().await?;
        assert!(commands::apply_operator_command(&mut tx, f.organization.scope, f.env.team_id, &f.actor, "operator-member", &member).await.is_err());
        tx.rollback().await?;
        let mut tx = f.pool.begin().await?;
        assert_eq!(commands::apply_operator_command(&mut tx, f.organization.scope, f.env.team_id, &f.actor, "provision", &create).await?, first);
        tx.rollback().await?;
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"configure\"]' WHERE administrator_id=$1").bind(f.actor.id).execute(&f.pool).await?;
        let mut tx = f.pool.begin().await?;
        assert!(commands::apply_operator_command(&mut tx, f.organization.scope, f.env.team_id, &f.actor, "provision", &create).await.is_err());
        tx.rollback().await?;
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_operator_bootstrap_is_disabled_explicit_and_current() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        operators::principal(&f).await?;
        let env = setup_test_environment(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.team_memberships(team_id,administrator_id,role) VALUES ($1,$2,'OWNER')")
            .bind(env.team_id).bind(f.actor.id).execute(&f.pool).await?;
        let mut first = f.pool.begin().await?;
        let created = bootstrap_default(&mut first, env.team_id, env.environment_id, &f.actor, "bootstrap").await?;
        assert!(!created.enabled);
        assert_eq!(created.operator.capabilities, BTreeSet::from([Capability::Configure]));
        // A competing bootstrap cannot pass the absence lock while this
        // transaction holds its uncommitted domain and receipt.
        let mut concurrent = f.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *concurrent).await?;
        assert!(matches!(bootstrap_default(&mut concurrent, env.team_id, env.environment_id, &f.actor, "bootstrap").await,
            Err(RepositoryError::Storage(sqlx::Error::Database(ref e))) if e.code().as_deref()==Some("55P03")));
        concurrent.rollback().await?;
        first.commit().await?;
        let mut retry = f.pool.begin().await?;
        assert_eq!(bootstrap_default(&mut retry, env.team_id, env.environment_id, &f.actor, "bootstrap").await?, created);
        retry.rollback().await?;
        let mut changed = f.pool.begin().await?;
        assert!(bootstrap_default(&mut changed, env.team_id, env.environment_id, &f.actor, "different-key").await.is_err());
        changed.rollback().await?;
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE id=$1").bind(created.operator.id).execute(&f.pool).await?;
        let mut retry = f.pool.begin().await?;
        assert!(bootstrap_default(&mut retry, env.team_id, env.environment_id, &f.actor, "bootstrap").await.is_err());
        retry.rollback().await?;
        cleanup_test_environment(&f.pool, &env).await?;
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and privileged isolated fault fixture"]
async fn pg_organizations_operator_audit_failure_rolls_back_grant_and_receipt() -> TestResult {
    let f = Fixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let result = async {
        configured(&f).await?;
        let administrator_id = target(&f).await?;
        let mut tx = admin.begin().await?;
        // Inject failure at the actual outbox write inside the command. Both
        // the trigger and its temporary function disappear on rollback.
        sqlx::query("CREATE FUNCTION pg_temp.organization_outbox_fault() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''injected organization outbox failure''; END'")
            .execute(&mut *tx).await?;
        sqlx::query("CREATE TRIGGER organization_outbox_fault BEFORE INSERT ON aegaeon.organization_authority_outbox FOR EACH ROW EXECUTE FUNCTION pg_temp.organization_outbox_fault()")
            .execute(&mut *tx).await?;
        let command = GrantCommand::Create { administrator_id, active: true, capabilities: vec![Capability::Reconcile] };
        assert!(matches!(apply_grant_command(&mut tx, f.organization.scope, f.env.team_id, &f.actor, "audit-rollback", &command).await,
            Err(RepositoryError::Storage(sqlx::Error::Database(ref e))) if e.code().as_deref()==Some("P0001")));
        tx.rollback().await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_operator_grants WHERE administrator_id=$1").bind(administrator_id).fetch_one(&f.pool).await?;
        assert_eq!(count, 0);
        let receipt: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_receipts WHERE domain_id=$1 AND idempotency_key='audit-rollback'").bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;
        assert_eq!(receipt, 0);
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE domain_id=$1 AND organization_id IS NULL")
            .bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;
        assert_eq!(events, 0);
        assert!(apply(&f, "audit-rollback", &command).await.is_ok());
        Ok(())
    }.await;
    admin.close().await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_operator_retained_quota_and_revision_exhaustion() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        configured(&f).await?;
        let command = GrantCommand::Create { administrator_id: target(&f).await?, active: true, capabilities: vec![Capability::Reconcile] };
        let created = apply(&f, "create", &command).await?;
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET revision=$2 WHERE id=$1")
            .bind(created.id).bind(i64::MAX-1).execute(&f.pool).await?;
        let revoke = GrantCommand::Update { id: created.id, expected_revision: i64::MAX-1, active: false, capabilities: vec![Capability::Reconcile] };
        let terminal = apply(&f, "last-revoke", &revoke).await?;
        assert_eq!(terminal.revision, i64::MAX);
        let reopen = GrantCommand::Update { id: created.id, expected_revision: i64::MAX, active: true, capabilities: vec![Capability::Reconcile] };
        assert!(matches!(apply(&f, "overflow", &reopen).await, Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        for _ in 2..crate::organizations::operators::MAX_OPERATORS {
            let administrator_id = target(&f).await?;
            sqlx::query("INSERT INTO aegaeon.organization_operator_grants(id,environment_id,domain_id,administrator_id,capabilities) VALUES ($1,$2,$3,$4,'[\"reconcile\"]')")
                .bind(Uuid::new_v4()).bind(f.organization.scope.environment_id)
                .bind(f.organization.scope.domain_id).bind(administrator_id).execute(&f.pool).await?;
        }
        let over_quota = GrantCommand::Create { administrator_id: target(&f).await?, active: false, capabilities: vec![Capability::Reconcile] };
        assert!(matches!(apply(&f, "over-quota", &over_quota).await, Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        // Retention exhaustion must not prevent revoking the last configurator.
        let id: Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.organization_operator_grants WHERE administrator_id=$1")
            .bind(f.actor.id).fetch_one(&f.pool).await?;
        let self_revoke = GrantCommand::Update { id, expected_revision: 1, active: false, capabilities: vec![Capability::Configure] };
        assert!(!apply(&f, "self-revoke", &self_revoke).await?.active);
        assert!(apply(&f, "self-revoke", &self_revoke).await.is_err());
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_operator_receipt_budget_reserves_only_active_revocation() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        configured(&f).await?;
        let command = GrantCommand::Create { administrator_id: target(&f).await?, active: true, capabilities: vec![Capability::Reconcile] };
        let created = apply(&f,"create",&command).await?;
        sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result) SELECT $1,$2,$3,'operator','fixture',$4,'domain.fixture',n::text,decode(repeat('ab',32),'hex'),'{}' FROM generate_series(1,9999) n")
            .bind(f.organization.scope.environment_id).bind(f.organization.scope.domain_id).bind(f.actor.id).bind(Uuid::nil()).execute(&f.pool).await?;
        assert_eq!(apply(&f,"create",&command).await?,created);
        let another = GrantCommand::Create { administrator_id: target(&f).await?, active: false, capabilities: vec![Capability::Reconcile] };
        assert!(matches!(apply(&f,"full",&another).await,Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        let revoke = GrantCommand::Revoke {id:created.id, expected_revision:1};
        let revoked = apply(&f,"revoke",&revoke).await?;
        assert!(!revoked.active);
        assert_eq!(apply(&f,"revoke",&revoke).await?,revoked);
        let noop = GrantCommand::Revoke {id:created.id, expected_revision:2};
        assert!(matches!(apply(&f,"noop",&noop).await,Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        let reactivate = GrantCommand::Update {id:created.id,expected_revision:2,active:true,capabilities:vec![Capability::Reconcile]};
        assert!(matches!(apply(&f,"reactivate",&reactivate).await,Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        Ok(())
    }.await;
    f.cleanup(result).await
}
