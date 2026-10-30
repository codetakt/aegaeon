use super::*;
use crate::organizations::operators::mutations::targets::{self, RegisterTarget, Target};

async fn configured(f: &Fixture) -> TestResult {
    operators::principal(f).await?;
    operators::grant(f, serde_json::json!(["configure"])).await
}

fn command(revision: i64, audience: &str) -> RegisterTarget {
    RegisterTarget {
        expected_revision: revision,
        target: Target {
            audience: audience.into(),
            management: false,
            introspection_clients: Vec::new(),
        },
    }
}

async fn apply(
    f: &Fixture,
    key: &str,
    command: &RegisterTarget,
) -> Result<targets::DomainConfiguration, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let value = targets::register(
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
async fn pg_organizations_targets_exact_scope_replay_and_current_authority() -> TestResult {
    let f = Fixture::new().await?;
    let other = Fixture::new().await?;
    let result = async {
        configured(&f).await?;
        configured(&other).await?;
        let audience = "urn:example:学校/É";
        let first = apply(&f, "first", &command(1, audience)).await?;
        assert_eq!(first.revision, 2);
        assert!(first.targets.iter().any(|t| t.audience == audience && !t.management));
        let second = apply(&f, "case", &command(2, "urn:example:学校/é")).await?;
        assert_eq!(second.revision, 3);
        assert_eq!(apply(&f, "first", &command(1, audience)).await?, first);
        assert!(matches!(apply(&f, "stale", &command(1, "new")).await,
            Err(RepositoryError::Authority(AuthorityError::PreconditionFailed))));
        assert!(matches!(apply(&f, "duplicate", &command(3, audience)).await,
            Err(RepositoryError::Authority(AuthorityError::Conflict))));
        assert!(matches!(apply(&f, "first", &command(1, "changed")).await,
            Err(RepositoryError::Authority(AuthorityError::Conflict))));
        assert!(apply(&other, "other-environment", &command(1, audience)).await.is_ok());
        for invalid in ["", " ", "urn:example:\n", &"学".repeat(683)] {
            assert!(apply(&f, "invalid", &command(3, invalid)).await.is_err());
        }
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE administrator_id=$1")
            .bind(f.actor.id).execute(&f.pool).await?;
        assert!(matches!(apply(&f, "first", &command(1, audience)).await,
            Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        let mut tx = f.pool.begin().await?;
        assert!(targets::read_configuration(&mut tx, f.organization.scope, f.env.team_id, f.actor.id).await.is_err());
        tx.rollback().await?;
        Ok(())
    }.await;
    other.cleanup(Ok(())).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_target_cross_domain_race_never_rebinds() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        configured(&f).await?;
        let other = Scope { domain_id: Uuid::new_v4(), ..f.organization.scope };
        sqlx::query("INSERT INTO aegaeon.authorization_domains(id,environment_id,name) VALUES($1,$2,'other')")
            .bind(other.domain_id).bind(other.environment_id).execute(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.organization_operator_grants(id,environment_id,domain_id,administrator_id,active,capabilities) VALUES($1,$2,$3,$4,true,'[\"configure\"]')")
            .bind(Uuid::new_v4()).bind(other.environment_id).bind(other.domain_id).bind(f.actor.id).execute(&f.pool).await?;
        let target = command(1, "urn:example:exclusive");
        let mut first = f.pool.begin().await?;
        targets::register(&mut first, f.organization.scope, f.env.team_id, &f.actor, "first", &target).await?;
        let mut competing = f.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *competing).await?;
        assert!(matches!(targets::register(&mut competing, other, f.env.team_id, &f.actor, "second", &target).await,
            Err(RepositoryError::Storage(sqlx::Error::Database(ref e))) if e.code().as_deref()==Some("55P03")));
        competing.rollback().await?;
        first.commit().await?;
        let mut retry = f.pool.begin().await?;
        assert!(matches!(targets::register(&mut retry, other, f.env.team_id, &f.actor, "second", &target).await,
            Err(RepositoryError::Authority(AuthorityError::Conflict))));
        retry.rollback().await?;
        let owner: Uuid = sqlx::query_scalar("SELECT domain_id FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND audience=$2")
            .bind(other.environment_id).bind(&target.target.audience).fetch_one(&f.pool).await?;
        assert_eq!(owner, f.organization.scope.domain_id);
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and privileged isolated fault fixture"]
async fn pg_organizations_target_audit_rollback_capacity_and_revision_reserve() -> TestResult {
    let f = Fixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let result = async {
        configured(&f).await?;
        let target = command(1, "urn:example:rollback");
        let mut tx = admin.begin().await?;
        sqlx::query("CREATE FUNCTION pg_temp.organization_target_fault() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''target audit fault''; END'")
            .execute(&mut *tx).await?;
        sqlx::query("CREATE TRIGGER organization_target_fault BEFORE INSERT ON aegaeon.organization_authority_outbox FOR EACH ROW EXECUTE FUNCTION pg_temp.organization_target_fault()")
            .execute(&mut *tx).await?;
        assert!(matches!(targets::register(&mut tx, f.organization.scope, f.env.team_id, &f.actor, "rollback", &target).await,
            Err(RepositoryError::Storage(sqlx::Error::Database(ref e))) if e.code().as_deref()==Some("P0001")));
        tx.rollback().await?;
        let mut tx = f.pool.begin().await?;
        let before = targets::read_configuration(&mut tx, f.organization.scope, f.env.team_id, f.actor.id).await?;
        assert_eq!(before.revision, 1);
        assert!(!before.targets.iter().any(|t| t.audience==target.target.audience));
        tx.rollback().await?;
        assert!(apply(&f, "rollback", &target).await.is_ok());
        let mut reserve = f.pool.begin().await?;
        sqlx::query("UPDATE aegaeon.authorization_domains SET revision=$2 WHERE id=$1")
            .bind(f.organization.scope.domain_id).bind(i64::MAX-1).execute(&mut *reserve).await?;
        assert!(matches!(targets::register(&mut reserve, f.organization.scope, f.env.team_id,
            &f.actor, "overflow", &command(i64::MAX-1,"overflow")).await,
            Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        reserve.rollback().await?;
        // Count and escaped-wire byte limits are independent. Retained fixture
        // rows represent already configured targets; no production quota reset.
        for i in 0..30 {
            sqlx::query("INSERT INTO aegaeon.authorization_domain_targets(environment_id,domain_id,audience) VALUES($1,$2,$3)")
                .bind(f.env.environment_id).bind(f.organization.scope.domain_id).bind(format!("target-{i}")).execute(&f.pool).await?;
        }
        assert!(matches!(apply(&f, "full", &command(2,"too-many")).await,
            Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        Ok(())
    }.await;
    admin.close().await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_target_encoded_capacity_keeps_existing_configuration_readable(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        configured(&f).await?;
        for i in 0..11 {
            let audience = format!("{}{:03}", "\"".repeat(2045), i);
            assert!(
                apply(&f, &format!("target-{i}"), &command(i + 1, &audience))
                    .await
                    .is_ok()
            );
        }
        let mut tx = f.pool.begin().await?;
        let before =
            targets::read_configuration(&mut tx, f.organization.scope, f.env.team_id, f.actor.id)
                .await?;
        assert!(serde_json::to_vec(&before)?.len() < 65_536);
        tx.rollback().await?;
        let audience = format!("{}012", "\"".repeat(2045));
        assert!(matches!(
            apply(&f, "too-large", &command(12, &audience)).await,
            Err(RepositoryError::Authority(AuthorityError::Exhausted))
        ));
        let mut tx = f.pool.begin().await?;
        assert_eq!(
            targets::read_configuration(&mut tx, f.organization.scope, f.env.team_id, f.actor.id)
                .await?,
            before
        );
        tx.rollback().await?;
        Ok(())
    }
    .await;
    f.cleanup(result).await
}
