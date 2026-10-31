use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use crate::web::test_support::{
    cleanup_test_environment, setup_test_environment, test_pg_pool, TestEnvironment, TestResult,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug)]
enum Query {
    ById,
    Subject,
    Locked,
    Ensure,
    Update,
}

impl Query {
    async fn call(
        self,
        pool: &PgPool,
        env: &TestEnvironment,
        user: Uuid,
        subject: &str,
    ) -> Result<bool, String> {
        let profile = match self {
            Self::ById => load_user_profile(pool, user)
                .await
                .map_err(|e| e.to_string())?,
            Self::Subject => load_user_profile_for_subject(pool, &env.issuer_url, subject)
                .await
                .map_err(|e| e.to_string())?,
            _ => return self.in_tx(pool, user).await,
        };
        if let Some(profile) = &profile {
            if profile.user_id != user.to_string() || profile.subject != subject {
                return Err("wrong profile identity".into());
            }
        }
        Ok(profile.is_some())
    }
    async fn in_tx(self, pool: &PgPool, user: Uuid) -> Result<bool, String> {
        let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
        let result = match self {
            Self::Ensure => match ensure_profile_row(&mut tx, user).await {
                Ok(()) => Ok(true),
                Err(sqlx::Error::Protocol(message))
                    if message == "foreign or missing Organizations profile owner" =>
                {
                    Ok(false)
                }
                Err(error) => Err(error.to_string()),
            },
            Self::Locked => match load_user_profile_for_update(&mut tx, user).await {
                Ok(_) => Ok(true),
                Err(UpdateProfileError::NotFound) => Ok(false),
                Err(error) => Err(format!("{error:?}")),
            },
            Self::Update => match update_user_profile(
                &mut tx,
                user,
                1,
                None,
                Some(true),
                Some(Some("updated".into())),
                None,
            )
            .await
            {
                Ok(profile) => {
                    Ok(profile.version == 2 && profile.display_name.as_deref() == Some("updated"))
                }
                Err(UpdateProfileError::NotFound) => Ok(false),
                Err(error) => Err(format!("{error:?}")),
            },
            _ => Err("unexpected transaction variant".into()),
        };
        // The fixture owns rollback even when the production helper refuses.
        tx.rollback().await.map_err(|e| e.to_string())?;
        result
    }
}

async fn seed(pool: &PgPool, env: &TestEnvironment, subject: &str) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')",
    )
    .bind(id)
    .bind(env.environment_id)
    .bind(subject)
    .execute(pool)
    .await?;
    Ok(id)
}

async fn scoped(query: Query) -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let first = setup_test_environment(&pool).await?;
    let second = setup_test_environment(&pool).await?;
    let subject = format!("profile-{}", Uuid::new_v4());
    let own = seed(&pool, &first, &subject).await?;
    let foreign = seed(&pool, &second, &subject).await?;
    let witness = CallerFixture::new(first.environment_id).await?;
    let result: TestResult = async {
        if !query.call(&pool, &first, own, &subject).await?
            || !query.call(&pool, &second, foreign, &subject).await?
        {
            return Err("ordinary profile call refused".into());
        }
        if !witness
            .run(query.call(&pool, &first, own, &subject))
            .await??
        {
            return Err("owned profile call refused".into());
        }
        if witness
            .run(query.call(&pool, &second, foreign, &subject))
            .await??
        {
            return Err(format!("{query:?} accepted foreign profile").into());
        }
        if witness.pending().await? != 0 {
            return Err("profile left pending work".into());
        }
        Ok(())
    }
    .await;
    let owner_cleanup = witness.finish().await.map_err(Into::into);
    let first_cleanup = cleanup_test_environment(&pool, &first)
        .await
        .map_err(Into::into);
    let second_cleanup = cleanup_test_environment(&pool, &second)
        .await
        .map_err(Into::into);
    pool.close().await;
    result
        .and(owner_cleanup)
        .and(first_cleanup)
        .and(second_cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual profile scope"]
async fn pg_organizations_user_profile_id_scope() -> TestResult {
    scoped(Query::ById).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual profile scope"]
async fn pg_organizations_user_profile_subject_scope() -> TestResult {
    scoped(Query::Subject).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual locked profile scope"]
async fn pg_organizations_user_profile_locked_scope() -> TestResult {
    scoped(Query::Locked).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual profile creation scope"]
async fn pg_organizations_user_profile_creation_scope() -> TestResult {
    scoped(Query::Ensure).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual profile update scope"]
async fn pg_organizations_user_profile_update_scope() -> TestResult {
    scoped(Query::Update).await
}

struct ReturnGate {
    entered: Arc<AtomicBool>,
    enabled: Arc<AtomicBool>,
    gate: Arc<Semaphore>,
}
impl ReturnGate {
    fn pool(setup: &PgPool) -> (PgPool, Self) {
        let entered = Arc::new(AtomicBool::new(false));
        let enabled = Arc::new(AtomicBool::new(true));
        let gate = Arc::new(Semaphore::new(0));
        let (seen, active, wait) = (entered.clone(), enabled.clone(), gate.clone());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_release(move |_, _| {
                let (seen, active, wait) = (seen.clone(), active.clone(), wait.clone());
                Box::pin(async move {
                    if active.load(Ordering::SeqCst) {
                        seen.store(true, Ordering::SeqCst);
                        wait.acquire_owned().await.unwrap().forget();
                    }
                    Ok(true)
                })
            })
            .connect_lazy_with(setup.connect_options().as_ref().clone());
        (
            pool,
            Self {
                entered,
                enabled,
                gate,
            },
        )
    }
    fn release(&self) {
        self.enabled.store(false, Ordering::SeqCst);
        self.gate.add_permits(8);
    }
}
async fn owns_return(query: Query) -> TestResult {
    let setup = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&setup).await?;
    let subject = format!("profile-{}", Uuid::new_v4());
    let user = seed(&setup, &env, &subject).await?;
    let witness = CallerFixture::new(env.environment_id).await?;
    let (pool, gate) = ReturnGate::pool(&setup);
    let result: TestResult = async {
        let work = witness.begin().await?;
        work.store_scope(async {
            let mut call = Box::pin(query.call(&pool, &env, user, &subject));
            let observed = async { while !gate.entered.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(5)).await; } };
            tokio::select! {
                r = &mut call => Err::<(), Box<dyn std::error::Error>>(format!("{query:?} returned before pool cleanup: {r:?}").into()),
                r = tokio::time::timeout(Duration::from_secs(5), observed) => { r?; drop(call); Ok(()) }
            }
        }).await??;
        let mut completion = tokio::spawn(work.complete());
        let early = tokio::time::timeout(Duration::from_millis(100), &mut completion).await;
        let pending = witness.pending().await?; gate.release();
        if early.is_ok() || pending != 1 { return Err("profile released witness before pool return".into()); }
        tokio::time::timeout(Duration::from_secs(5), completion).await???;
        if witness.pending().await? != 0 { return Err("completed profile read remained pending".into()); }
        if !witness.run(query.call(&pool, &env, user, &subject)).await?? { return Err("normal profile absent".into()); }
        Ok(())
    }.await;
    gate.release();
    pool.close().await;
    let owner_cleanup = witness.finish().await.map_err(Into::into);
    let cleanup = cleanup_test_environment(&setup, &env)
        .await
        .map_err(Into::into);
    setup.close().await;
    result.and(owner_cleanup).and(cleanup)
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual profile cancellation and pool return"]
async fn pg_organizations_user_profile_id_owns_return() -> TestResult {
    owns_return(Query::ById).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual profile cancellation and pool return"]
async fn pg_organizations_user_profile_subject_owns_return() -> TestResult {
    owns_return(Query::Subject).await
}
