use super::repository::{self, ActorKind, AuditActor, MembershipUpdate, RepositoryError};
use super::*;
use crate::web::test_support::{cleanup_test_environment, setup_test_environment, TestEnvironment};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::BTreeSet;
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

mod audit_transitions;
mod clients;
pub(crate) mod consent;
mod identifiers;
mod identity;
pub(crate) mod import;
mod invitations;
mod lifecycle;
mod operator_mutations;
mod operators;
mod ownership;
mod recipients;
mod role_policy;
mod selected;
mod snapshot;
mod support_grants;
pub(crate) mod support_policy;
mod targets;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_receipts_replay_creation_once_and_reject_changed_body() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        operators::principal(&f).await?;
        operators::grant(&f, serde_json::json!(["provision"])).await?;
        let command = super::commands::Command::Create { external_id: "new-school".into() };
        let mut first = f.pool.begin().await?;
        let created = super::commands::apply_operator_command(&mut first, f.organization.scope, f.env.team_id, &f.actor, "create-once", &command).await?;
        first.commit().await?;
        let mut second = f.pool.begin().await?;
        let mut actor = f.actor.clone();
        actor.request_id = "retry-request".into();
        let replay = super::commands::apply_operator_command(&mut second, f.organization.scope, f.env.team_id, &actor, "create-once", &command).await?;
        assert_eq!(created, replay);
        second.commit().await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.application_organizations WHERE domain_id=$1 AND external_id='new-school'")
            .bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;
        assert_eq!(count, 1);
        let different = super::commands::Command::Create { external_id: "different-school".into() };
        let mut tx = f.pool.begin().await?;
        assert!(matches!(super::commands::apply_operator_command(&mut tx, f.organization.scope, f.env.team_id, &actor, "create-once", &different).await,
            Err(RepositoryError::Authority(AuthorityError::Conflict))));
        tx.rollback().await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_receipts WHERE domain_id=$1")
            .bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;
        assert_eq!(count, 1);
        Ok(())
    }.await;
    f.cleanup(result).await
}

pub(crate) struct Fixture {
    pub(crate) pool: PgPool,
    pub(crate) env: TestEnvironment,
    pub(crate) organization: Organization,
    pub(crate) users: [Uuid; 2],
    pub(crate) actor: AuditActor,
}

impl Fixture {
    pub(crate) async fn in_epoch(
        &self,
        future: impl std::future::Future<Output = TestResult>,
    ) -> TestResult {
        witness::tests::scope_fixture::with_environment(self.env.environment_id, future)
            .await
            .map_err(|error| format!("{error:#}"))?
    }

    async fn access(&self) -> Result<AccessDecision, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let request = AccessRequest {
            detail_type: ORGANIZATION_ACCESS_TYPE.into(),
            admin_access_grant_id: None,
            identifier: self.organization.external_id.clone(),
            privileges: None,
        };
        let organization = repository::resolve_access_organization(
            &mut tx,
            self.organization.scope,
            "management-api",
            &request,
        )
        .await?;
        let member = repository::membership(&mut tx, &organization, self.users[0])
            .await?
            .ok_or(AuthorityError::Invalid)?;
        let roles = repository::roles(&mut tx, self.organization.scope).await?;
        let binding = Binding {
            scope: self.organization.scope,
            issuer: self.env.issuer_url.clone(),
            client_id: "delegated-client".into(),
            client_registration_id: Uuid::new_v4(),
            subject: format!("organization-user-{}", self.users[0]),
            user_id: self.users[0],
            root_id: "captured-root".into(),
            dpop_jkt: "captured-key".into(),
        };
        let allowed = BTreeSet::from([super::delegation::MANAGE_MEMBERS.into()]);
        let ceiling = AuthorizationCeiling {
            version: 1,
            binding,
            expires_at: 1000,
            audiences: std::collections::BTreeMap::from([(
                "management-api".into(),
                allowed.clone(),
            )]),
            memberships: std::collections::BTreeMap::from([(
                self.organization.id,
                AuthorizationCeiling::capture_membership(&self.organization, &member, &roles)?,
            )]),
        };
        Ok(AccessDecision::authorize(AccessInput {
            ceiling: &ceiling,
            authenticated: &ceiling.binding,
            request: &request,
            audience: "management-api",
            current_client_privileges: &allowed,
            organization: &organization,
            member: &member,
            definitions: &roles,
            parent_expires_at: 1000,
            now: 100,
        })?)
    }

    async fn delegate(
        &self,
        access: &AccessDecision,
        key: &str,
    ) -> Result<super::commands::CommandResult, RepositoryError> {
        let actor = AuditActor {
            basis: None,
            id: access.binding.user_id,
            kind: ActorKind::Member,
            client_id: access.binding.client_id.clone(),
            client_registration_id: Some(access.binding.client_registration_id),
            ..self.actor.clone()
        };
        let mut tx = self.pool.begin().await?;
        let member = repository::membership(&mut tx, &self.organization, self.users[0])
            .await?
            .ok_or(AuthorityError::Invalid)?;
        let roles = repository::roles(&mut tx, self.organization.scope).await?;
        let assigned = BTreeSet::from(["reader".into()]);
        let authority = super::delegation::DelegationInput {
            access,
            authenticated: &access.binding,
            management_audience: "management-api",
            current_client_privileges: &BTreeSet::from([super::delegation::MANAGE_MEMBERS.into()]),
            organization: &self.organization,
            actor_membership: &member,
            definitions: &roles,
            assign_roles: &assigned,
            now: 100,
        };
        let command = super::commands::Command::SetMember {
            organization_id: self.organization.id,
            update: MembershipUpdate {
                user_id: self.users[1],
                expected_revision: 1,
                state: MembershipState::Active,
                roles: assigned.clone(),
            },
        };
        let result = super::commands::apply_member_command(
            &mut tx,
            self.organization.scope,
            &actor,
            key,
            &command,
            &authority,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    pub(crate) async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_identifier("opaque-01").await
    }

    pub(crate) async fn with_identifier(
        identifier: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
            .await?;
        let env = setup_test_environment(&pool).await?;
        let scope = Scope {
            environment_id: env.environment_id,
            domain_id: Uuid::new_v4(),
        };
        sqlx::query("INSERT INTO aegaeon.authorization_domains (id,environment_id,name,enabled,is_default) VALUES ($1,$2,'default',true,true)")
            .bind(scope.domain_id).bind(scope.environment_id).execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.authorization_domain_targets (environment_id,domain_id,audience,management) VALUES ($1,$2,'management-api',true)")
            .bind(scope.environment_id).bind(scope.domain_id).execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.organization_role_definitions (environment_id,domain_id,role_key,privileges,manages_members,assignable_roles) VALUES ($1,$2,'admin','[\"organization.members.manage\"]',true,'[\"admin\",\"reader\"]'), ($1,$2,'reader','[\"documents.read\"]',false,'[]')")
            .bind(scope.environment_id).bind(scope.domain_id).execute(&pool).await?;
        let users = [Uuid::new_v4(), Uuid::new_v4()];
        for user in users {
            sqlx::query("INSERT INTO aegaeon.end_users (id,environment_id,subject,status) VALUES ($1,$2,$3,'ACTIVE')")
                .bind(user).bind(scope.environment_id).bind(format!("organization-user-{user}"))
                .execute(&pool).await?;
        }
        let organization = Organization {
            scope,
            id: Uuid::new_v4(),
            external_id: identifier.into(),
            state: OrganizationState::Provisioning,
            revision: 1,
            grant_generation: 1,
        };
        let actor = AuditActor {
            basis: None,
            id: Uuid::new_v4(),
            kind: ActorKind::Operator,
            client_id: "operator-console".into(),
            client_registration_id: None,
            request_id: "fixture-create".into(),
            reason: "Fixture authority setup".into(),
        };
        let mut tx = pool.begin().await?;
        repository::create_organization(&mut tx, &organization, &actor).await?;
        for user in users {
            repository::update_membership(
                &mut tx,
                scope,
                organization.id,
                MembershipUpdate {
                    user_id: user,
                    expected_revision: 0,
                    state: MembershipState::Active,
                    roles: BTreeSet::from(["admin".into()]),
                },
                &actor,
            )
            .await?;
        }
        let organization = repository::transition_organization(
            &mut tx,
            scope,
            organization.id,
            1,
            OrganizationState::Active,
            &actor,
        )
        .await?;
        tx.commit().await?;
        Ok(Self {
            pool,
            env,
            organization,
            users,
            actor,
        })
    }

    pub(crate) async fn cleanup(self, result: TestResult) -> TestResult {
        // Runtime cannot erase retained authority history. The isolated fixture
        // database is removed by its owner after all cases have completed.
        cleanup_test_environment(&self.pool, &self.env).await?;
        // Each test owns a runtime. Drain checked-out connections and their
        // admission owners before that runtime exits; retained rows stay intact.
        tokio::time::timeout(std::time::Duration::from_secs(30), self.pool.close()).await?;
        result
    }

    async fn remove(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        user: Uuid,
    ) -> Result<Membership, RepositoryError> {
        repository::update_membership(
            tx,
            self.organization.scope,
            self.organization.id,
            MembershipUpdate {
                user_id: user,
                expected_revision: 1,
                state: MembershipState::Removed,
                roles: BTreeSet::new(),
            },
            &self.actor,
        )
        .await
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_delegation_rechecks_identity_before_idempotent_replay() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let access = f.access().await?;
        let first = f.delegate(&access, "delegate-once").await?;
        let second = f.delegate(&access, "delegate-once").await?;
        assert_eq!(first, second);
        // A newly authorized registration with the same public client_id has
        // its own receipt namespace. It must observe the stale CAS, not obtain
        // a successful receipt belonging to the previous registration.
        let mut recreated_client = access.clone();
        recreated_client.binding.client_registration_id = Uuid::new_v4();
        recreated_client.binding.root_id = "new-registration-root".into();
        assert!(matches!(
            f.delegate(&recreated_client, "delegate-once").await,
            Err(RepositoryError::Authority(AuthorityError::Conflict))
        ));
        sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE id=$1")
            .bind(f.users[0])
            .execute(&f.pool)
            .await?;
        assert!(matches!(
            f.delegate(&access, "delegate-once").await,
            Err(RepositoryError::Authority(AuthorityError::Forbidden))
        ));
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_limited_delegate_cannot_strip_a_stronger_role() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET assignable_roles='[\"reader\"]' WHERE domain_id=$1 AND role_key='admin'")
            .bind(f.organization.scope.domain_id).execute(&f.pool).await?;
        let access = f.access().await?;
        assert!(matches!(f.delegate(&access, "limited-demotion").await,
            Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        let mut tx = f.pool.begin().await?;
        let member = repository::membership(&mut tx, &f.organization, f.users[1]).await?.ok_or("member")?;
        assert_eq!(member.roles, BTreeSet::from(["admin".into()]));
        assert_eq!(member.revision, 1);
        tx.rollback().await?;
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_concurrent_last_administrator_removal_is_serialized() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let mut first = f.pool.begin().await?;
        f.remove(&mut first, f.users[0]).await?;
        let mut second = f.pool.begin().await?;
        let removal = f.remove(&mut second, f.users[1]);
        tokio::pin!(removal);
        assert!(tokio::time::timeout(std::time::Duration::from_millis(50), &mut removal).await.is_err());
        first.commit().await?;
        assert!(matches!(removal.await, Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1 AND state='active'")
            .bind(f.organization.id).fetch_one(&f.pool).await?;
        assert_eq!(count, 1);
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_reject_cross_environment_membership_and_reused_external_id() -> TestResult
{
    let f = Fixture::new().await?;
    let result = async {
        let foreign = setup_test_environment(&f.pool).await?;
        let foreign_user = Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.end_users (id,environment_id,subject,status) VALUES ($1,$2,'foreign','ACTIVE')")
            .bind(foreign_user).bind(foreign.environment_id).execute(&f.pool).await?;
        let mut tx = f.pool.begin().await?;
        let rejected = sqlx::query("INSERT INTO aegaeon.organization_memberships (environment_id,domain_id,organization_id,end_user_id,incarnation,state,roles) VALUES ($1,$2,$3,$4,$5,'active','[]')")
            .bind(f.organization.scope.environment_id).bind(f.organization.scope.domain_id)
            .bind(f.organization.id).bind(foreign_user).bind(Uuid::new_v4()).execute(&mut *tx).await;
        assert_eq!(rejected.unwrap_err().as_database_error().and_then(|e| e.code()).as_deref(), Some("23503"));
        tx.rollback().await?;
        cleanup_test_environment(&f.pool, &foreign).await?;
        let mut tx = f.pool.begin().await?;
        repository::transition_organization(&mut tx, f.organization.scope, f.organization.id,
            f.organization.revision, OrganizationState::Deleted, &f.actor).await?;
        tx.commit().await?;
        let duplicate = Organization { id: Uuid::new_v4(), state: OrganizationState::Provisioning,
            revision: 1, grant_generation: 1, ..f.organization.clone() };
        let mut tx = f.pool.begin().await?;
        assert!(repository::create_organization(&mut tx, &duplicate, &f.actor).await.is_err());
        tx.rollback().await?;
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_audit_outbox_failure_rolls_back_authority_change() -> TestResult {
    let f = Fixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let runtime: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&f.pool)
        .await?;
    let result = async {
        // An actual database failure after the membership UPDATE must poison
        // the transaction, not leave a committed change without its outbox.
        let mut tx = admin.begin().await?;
        sqlx::query("ALTER TABLE aegaeon.organization_authority_outbox ADD CONSTRAINT organization_fixture_refuse CHECK (attempts < 0) NOT VALID")
            .execute(&mut *tx).await?;
        sqlx::query("SELECT set_config('role',$1,true)").bind(&runtime).execute(&mut *tx).await?;
        assert!(f.remove(&mut tx, f.users[0]).await.is_err());
        tx.rollback().await?;
        let mut tx = f.pool.begin().await?;
        let member = repository::membership(&mut tx, &f.organization, f.users[0]).await?.ok_or("member")?;
        assert_eq!(member.state, MembershipState::Active);
        assert_eq!(member.revision, 1);
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE organization_id=$1")
            .bind(f.organization.id).fetch_one(&mut *tx).await?;
        let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_outbox o JOIN aegaeon.organization_authority_events e ON e.id=o.event_id WHERE e.organization_id=$1")
            .bind(f.organization.id).fetch_one(&mut *tx).await?;
        assert_eq!((events,pending), (4,4));
        tx.rollback().await?;
        Ok(())
    }.await;
    admin.close().await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_stale_revision_and_removed_membership_are_not_reactivated() -> TestResult
{
    let f = Fixture::new().await?;
    let result = async {
        let mut tx = f.pool.begin().await?;
        f.remove(&mut tx, f.users[0]).await?;
        tx.commit().await?;
        let mut tx = f.pool.begin().await?;
        assert!(matches!(
            f.remove(&mut tx, f.users[0]).await,
            Err(RepositoryError::Authority(AuthorityError::Conflict))
        ));
        tx.rollback().await?;
        let mut tx = f.pool.begin().await?;
        let restored = repository::update_membership(
            &mut tx,
            f.organization.scope,
            f.organization.id,
            MembershipUpdate {
                user_id: f.users[0],
                expected_revision: 2,
                state: MembershipState::Active,
                roles: BTreeSet::from(["admin".into()]),
            },
            &f.actor,
        )
        .await;
        assert!(matches!(
            restored,
            Err(RepositoryError::Authority(AuthorityError::Forbidden))
        ));
        tx.rollback().await?;
        Ok(())
    }
    .await;
    f.cleanup(result).await
}
