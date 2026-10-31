use super::*;
use crate::organizations::commands::{apply_operator_command, Command, CommandResult};

async fn active(f: &InvitationFixture) -> Result<Organization, Box<dyn std::error::Error>> {
    let mut tx = f.base.pool.begin().await?;
    repository::update_membership(
        &mut tx,
        f.request_scope(),
        f.request.organization_id,
        MembershipUpdate {
            user_id: f.base.users[0],
            expected_revision: 0,
            state: MembershipState::Active,
            roles: BTreeSet::from(["admin".into()]),
        },
        &f.base.actor,
    )
    .await?;
    let org = repository::transition_organization(
        &mut tx,
        f.request_scope(),
        f.request.organization_id,
        1,
        OrganizationState::Active,
        &f.base.actor,
    )
    .await?;
    tx.commit().await?;
    Ok(org)
}
impl InvitationFixture {
    fn request_scope(&self) -> Scope {
        self.base.organization.scope
    }
    async fn recovery(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        revision: i64,
    ) -> Result<CommandResult, RepositoryError> {
        apply_operator_command(
            tx,
            self.request_scope(),
            self.base.env.team_id,
            &self.base.actor,
            "recovery-once",
            &Command::PrepareAdministratorRecovery {
                organization_id: self.request.organization_id,
                expected_revision: revision,
            },
        )
        .await
    }
    async fn old_status(&self, status: &str) -> TestResult {
        sqlx::query("UPDATE aegaeon.end_users SET status=$2::aegaeon.end_user_status WHERE id=$1")
            .bind(self.base.users[0])
            .bind(status)
            .execute(&self.base.pool)
            .await?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_administrator_recovery_preserves_members_and_accepts_once() -> TestResult
{
    let mut f = InvitationFixture::new().await?;
    let result = crate::organizations::witness::tests::scope_fixture::with_environment(
        f.base.env.environment_id,
        async {
            let active = active(&f).await?;
            let mut tx = f.base.pool.begin().await?;
            assert!(
                f.recovery(&mut tx, active.revision).await.is_err(),
                "live administrator prevents recovery"
            );
            tx.rollback().await?;
            f.old_status("SUSPENDED").await?;
            let mut tx = f.base.pool.begin().await?;
            let CommandResult::Organization(recovering) =
                f.recovery(&mut tx, active.revision).await?
            else {
                return Err("organization expected".into());
            };
            let mut second = f.base.pool.begin().await?;
            {
                let replay = f.recovery(&mut second, active.revision);
                tokio::pin!(replay);
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(50), &mut replay)
                        .await
                        .is_err()
                );
                tx.commit().await?;
                assert_eq!(
                    replay.await?,
                    CommandResult::Organization(recovering.clone())
                );
            }
            second.commit().await?;
            assert_eq!(
                (recovering.state, recovering.grant_generation),
                (OrganizationState::Provisioning, active.grant_generation + 1)
            );
            f.request.expected_revision = recovering.revision;
            let (id, secret, challenge, proof) = f.prepared().await?;
            f.old_status("ACTIVE").await?;
            let mut tx = f.base.pool.begin().await?;
            assert!(
                invite::accept_first_admin(&mut tx, &f.acceptance(id, &secret, challenge, &proof))
                    .await
                    .is_err(),
                "resumed administrator prevents replacement"
            );
            tx.rollback().await?;
            f.old_status("SUSPENDED").await?;
            let input = f.acceptance(id, &secret, challenge, &proof);
            let mut tx = f.base.pool.begin().await?;
            let member = invite::accept_first_admin(&mut tx, &input).await?;
            let mut second = f.base.pool.begin().await?;
            {
                let replay = invite::accept_first_admin(&mut second, &input);
                tokio::pin!(replay);
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(50), &mut replay)
                        .await
                        .is_err()
                );
                tx.commit().await?;
                assert_eq!(replay.await?, member);
            }
            second.commit().await?;
            let mut tx = f.base.pool.begin().await?;
            let restored =
                repository::lock_organization(&mut tx, f.request_scope(), active.id).await?;
            assert_eq!(
                (restored.state, restored.grant_generation),
                (OrganizationState::Active, active.grant_generation + 2)
            );
            let old = repository::membership(&mut tx, &restored, f.base.users[0])
                .await?
                .ok_or("retained member")?;
            assert_eq!(
                (old.state, old.revision, old.grant_generation),
                (MembershipState::Active, 1, 1)
            );
            assert_eq!(old.roles, BTreeSet::from(["admin".into()]));
            assert_ne!(member.user_id, old.user_id);
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1",
            )
            .bind(active.id)
            .fetch_one(&mut *tx)
            .await?;
            assert_eq!(count, 2);
            tx.rollback().await?;
            Ok(())
        },
    )
    .await
    .map_err(|error| -> Box<dyn std::error::Error> { format!("{error:#}").into() })
    .and_then(std::convert::identity);
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_administrator_recovery_audit_failure_rolls_back_and_resume_race_refuses(
) -> TestResult {
    let f = InvitationFixture::new().await?;
    let result=f.base.in_epoch(async {
        let active=active(&f).await?;f.old_status("SUSPENDED").await?;
        let admin=crate::web::test_support::test_admin_pool(&f.base.pool).await?;
        let guard=format!("recovery_fault_{}",Uuid::new_v4().simple());
        sqlx::query(&format!("ALTER TABLE aegaeon.organization_authority_events ADD CONSTRAINT {guard} CHECK(organization_id<>'{}'::uuid OR event_type<>'organization.administrator_recovery_prepared') NOT VALID",active.id)).execute(&admin).await?;
        let mut tx=f.base.pool.begin().await?;let result=f.recovery(&mut tx,active.revision).await;tx.rollback().await?;
        sqlx::query(&format!("ALTER TABLE aegaeon.organization_authority_events DROP CONSTRAINT {guard}")).execute(&admin).await?;
        assert!(matches!(result,Err(RepositoryError::Storage(_))));
        let mut tx=f.base.pool.begin().await?;
        assert_eq!(repository::lock_organization(&mut tx,f.request_scope(),active.id).await?,active);tx.rollback().await?;
        let mut resume=f.base.pool.begin().await?;
        sqlx::query("UPDATE aegaeon.end_users SET status='ACTIVE' WHERE id=$1").bind(f.base.users[0]).execute(&mut *resume).await?;
        let mut recovery=f.base.pool.begin().await?;
        {
            let pending=f.recovery(&mut recovery,active.revision);tokio::pin!(pending);
            assert!(tokio::time::timeout(std::time::Duration::from_millis(50),&mut pending).await.is_err());
            resume.commit().await?;
            assert!(matches!(pending.await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        }
        recovery.rollback().await?;
        Ok(())
    }).await;
    f.base.cleanup(result).await
}
