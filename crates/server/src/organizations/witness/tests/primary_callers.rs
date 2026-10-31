use super::caller_fixture::CallerFixture;
use crate::{local_credentials as credentials, organizations::repository_tests::Fixture};
use sqlx::PgPool;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Semaphore;

type TestResult = crate::web::test_support::TestResult;
const PASSWORD: &str = "owned-credential-fixture-password";

#[derive(Clone, Copy, Debug)]
enum Caller {
    Cleanup,
    Environment,
    Authentication,
    CredentialState,
    Recovery,
}

impl Caller {
    async fn call(self, pool: &PgPool, f: &Fixture, token: &str) -> TestResult {
        match self {
            Self::Cleanup => {
                assert_eq!(
                    crate::web::cleanup_expired_authorization_transactions(
                        pool,
                        f.env.environment_id
                    )
                    .await?,
                    1
                );
            }
            Self::Environment => {
                assert_eq!(
                    credentials::load_runtime_environment_context(pool, &f.env.issuer_url)
                        .await?
                        .ok_or("environment")?
                        .environment_id,
                    f.env.environment_id
                );
            }
            Self::Authentication => {
                let user = credentials::authenticate_local_user(
                    pool,
                    &f.env.issuer_url,
                    &format!("organization-user-{}", f.users[0]),
                    PASSWORD,
                )
                .await?
                .ok_or("authenticated user")?;
                assert_eq!(user.end_user_id, f.users[0]);
            }
            Self::CredentialState => {
                let state = credentials::load_user_credential_state(pool, f.users[0]).await?;
                assert!(state.password.is_some());
                assert_eq!(state.recovery_tokens.len(), 1);
            }
            Self::Recovery => {
                let user = credentials::redeem_recovery_token(
                    pool,
                    &f.env.issuer_url,
                    token,
                    credentials::RecoveryTokenPurpose::PasswordReset,
                    "replacement-fixture-hash",
                    "owned-recovery",
                )
                .await?
                .ok_or("redeemed token")?;
                assert_eq!(user.subject, format!("organization-user-{}", f.users[0]));
            }
        }
        Ok(())
    }
}

struct ReturnGate {
    enabled: Arc<AtomicBool>,
    entered: Arc<AtomicBool>,
    gate: Arc<Semaphore>,
}

impl ReturnGate {
    fn pool(f: &Fixture, caller: Caller) -> (PgPool, Self) {
        let enabled = Arc::new(AtomicBool::new(true));
        let entered = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(Semaphore::new(0));
        let returns = Arc::new(AtomicUsize::new(0));
        let target = if matches!(caller, Caller::Authentication | Caller::Recovery) {
            2
        } else {
            1
        };
        let (active, observed, wait) = (enabled.clone(), entered.clone(), gate.clone());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_release(move |_, _| {
                let (active, observed, wait, returns) = (
                    active.clone(),
                    observed.clone(),
                    wait.clone(),
                    returns.clone(),
                );
                Box::pin(async move {
                    if active.load(Ordering::SeqCst)
                        && returns.fetch_add(1, Ordering::SeqCst) + 1 == target
                    {
                        observed.store(true, Ordering::SeqCst);
                        wait.acquire_owned().await.unwrap().forget();
                    }
                    Ok(true)
                })
            })
            .connect_lazy_with(f.pool.connect_options().as_ref().clone());
        (
            pool,
            Self {
                enabled,
                entered,
                gate,
            },
        )
    }

    fn release(&self) {
        self.enabled.store(false, Ordering::SeqCst);
        self.gate.add_permits(8);
    }
}

async fn setup(f: &Fixture) -> Result<String, Box<dyn std::error::Error>> {
    let hash = credentials::hash_password(PASSWORD)?;
    sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash,status) VALUES($1,$2,'ACTIVE')")
        .bind(f.users[0]).bind(hash).execute(&f.pool).await?;
    sqlx::query("INSERT INTO aegaeon.authorization_consents(environment_id,issuer,subject,session_sha256,token_sha256,authorize_uri,request_snapshot,expires_at) VALUES($1,$2,'cleanup-owner','session',gen_random_uuid()::text,'/authorize','{}',statement_timestamp()-interval '1 minute')")
        .bind(f.env.environment_id).bind(&f.env.issuer_url).execute(&f.pool).await?;
    let mut tx = f.pool.begin().await?;
    let token = credentials::issue_recovery_token(
        &mut tx,
        f.users[0],
        credentials::RecoveryTokenPurpose::PasswordReset,
        300,
        None,
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(token.token)
}

async fn exercise(
    caller: Caller,
    f: &Fixture,
    witness: &CallerFixture,
    pool: &PgPool,
    gate: &ReturnGate,
    token: &str,
) -> TestResult {
    let work = witness.begin().await?;
    work.store_scope(async {
        let mut call = Box::pin(caller.call(pool, f, token));
        let entered = async {
            while !gate.entered.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(5)).await; }
        };
        tokio::select! {
            result = &mut call => Err::<(), Box<dyn std::error::Error>>(format!("{caller:?} returned before actual pool cleanup: {result:?}").into()),
            result = tokio::time::timeout(Duration::from_secs(5), entered) => { result?; drop(call); Ok(()) }
        }
    }).await??;
    let mut completion = tokio::spawn(work.complete());
    let early = tokio::time::timeout(Duration::from_millis(100), &mut completion).await;
    let pending = witness.pending().await?;
    gate.release();
    let premature = match early {
        Ok(result) => {
            result??;
            true
        }
        Err(_) => {
            tokio::time::timeout(Duration::from_secs(5), completion).await???;
            false
        }
    };
    if premature || pending != 1 {
        return Err(format!("{caller:?} completed witness before actual connection return").into());
    }
    assert_eq!(witness.pending().await?, 0);
    if matches!(caller, Caller::Cleanup) {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.authorization_consents WHERE environment_id=$1",
        )
        .bind(f.env.environment_id)
        .fetch_one(&f.pool)
        .await?;
        assert_eq!(count, 0);
    } else if matches!(caller, Caller::Recovery) {
        assert!(credentials::redeem_recovery_token(
            &f.pool,
            &f.env.issuer_url,
            token,
            credentials::RecoveryTokenPurpose::PasswordReset,
            "must-not-replay",
            "replay"
        )
        .await?
        .is_none());
        let hash: String = sqlx::query_scalar(
            "SELECT password_hash FROM aegaeon.end_user_password_credentials WHERE end_user_id=$1",
        )
        .bind(f.users[0])
        .fetch_one(&f.pool)
        .await?;
        assert_eq!(hash, "replacement-fixture-hash");
    } else {
        witness.run(caller.call(&f.pool, f, token)).await??;
    }
    Ok(())
}

async fn run(caller: Caller) -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
    let (pool, gate) = ReturnGate::pool(&f, caller);
    let result = async {
        let token = setup(&f).await?;
        exercise(caller, &f, &witness, &pool, &gate, &token).await
    }
    .await;
    gate.release();
    pool.close().await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
    f.cleanup(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual cleanup mutation and retained pool return"]
async fn pg_organizations_primary_cleanup_owns_return() -> TestResult {
    run(Caller::Cleanup).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual issuer environment read and retained pool return"]
async fn pg_organizations_primary_environment_owns_return() -> TestResult {
    run(Caller::Environment).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual password validation and retained pool return"]
async fn pg_organizations_primary_authentication_owns_return() -> TestResult {
    run(Caller::Authentication).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual credential state and retained pool return"]
async fn pg_organizations_primary_credentials_own_return() -> TestResult {
    run(Caller::CredentialState).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual one-time redemption and retained pool return"]
async fn pg_organizations_primary_recovery_owns_return() -> TestResult {
    run(Caller::Recovery).await
}
