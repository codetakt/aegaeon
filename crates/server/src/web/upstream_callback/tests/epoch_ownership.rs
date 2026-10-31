use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug)]
enum Caller {
    Callback,
    CurrentConnection,
    AuthorizeConnection,
    LocalAudit,
    FailureAudit,
    OAuthAudit,
}

impl Caller {
    async fn call(self, f: &Fixture) -> TestResult {
        match self {
            Self::Callback => {
                let response = f.callback(&f.request, "owned-upstream", None).await?;
                if !response.status().is_redirection() {
                    return Err(format!("callback {}", response.status()).into());
                }
            }
            Self::CurrentConnection => {
                let mut request = f.request.clone();
                super::super::super::upstream_callback_connection::validate_and_hydrate_upstream_callback_connection(
                    &f.state.db_pool, &mut request, "jit-test", &f.env.issuer_url,
                ).await.map_err(|r| format!("current connection {}", r.status()))?;
            }
            Self::AuthorizeConnection => {
                crate::web::upstream_authorize::load_upstream_connection(
                    &f.state.db_pool,
                    &f.env.issuer_url,
                    "jit-test",
                )
                .await?;
            }
            Self::LocalAudit => {
                use crate::web::local_auth_audit::{write_local_auth_audit, LocalAuthAuditEvent};
                let environment = crate::local_credentials::RuntimeEnvironmentContext {
                    team_id: f.env.team_id,
                    tenant_id: f.env.tenant_id,
                    environment_id: f.env.environment_id,
                };
                write_local_auth_audit(
                    &f.state.db_pool,
                    LocalAuthAuditEvent {
                        environment: &environment,
                        event_type: "owned-local-test",
                        outcome: "failure",
                        severity: "error",
                        actor_type: "end_user",
                        actor_id: None,
                        target_type: "login",
                        target_id: None,
                        request_id: "owned-upstream",
                        data: json!({}),
                    },
                )
                .await?;
            }
            Self::FailureAudit => {
                record_upstream_callback_session_failure_audit(
                    &f.state.db_pool,
                    &f.request,
                    "owned-subject",
                    "owned-upstream",
                    "fixture",
                )
                .await;
            }
            Self::OAuthAudit => {
                use crate::web::oauth_audit::{require_oauth_audit, OAuthAuditEvent};
                require_oauth_audit(
                    &f.state,
                    &f.env.issuer_url,
                    OAuthAuditEvent {
                        event_type: "owned-oauth-test",
                        category: "token",
                        outcome: "requested",
                        severity: "info",
                        actor_type: "client",
                        actor_id: Some("fixture"),
                        target_type: "oauth_grant",
                        target_id: None,
                        request_id: "owned-upstream",
                        data: json!({}),
                    },
                )
                .await
                .map_err(|r| format!("OAuth audit {}", r.status()))?;
            }
        }
        Ok(())
    }
}

async fn fixture() -> TestResult<Fixture> {
    let mut f = Fixture::new().await?;
    // Use the exact persisted connection tuple for the live currentness reader.
    f.request.issuer = "https://issuer.example".into();
    f.request.client_id = "client".into();
    f.request.client_auth_method = "none".into();
    Ok(f)
}

async fn finish(f: Fixture, witness: CallerFixture, result: TestResult) -> TestResult {
    let witness_cleanup = witness.finish().await.map_err(Into::into);
    let cleanup = f.cleanup().await;
    f.pool.close().await;
    result.and(witness_cleanup).and(cleanup)
}

async fn owns_return(caller: Caller) -> TestResult {
    let mut f = fixture().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
    let entered = Arc::new(AtomicBool::new(false));
    let enabled = Arc::new(AtomicBool::new(true));
    let gate = Arc::new(Semaphore::new(0));
    let returns = Arc::new(AtomicUsize::new(0));
    let target = if matches!(caller, Caller::OAuthAudit) {
        2
    } else {
        1
    };
    let (observed, active, wait) = (entered.clone(), enabled.clone(), gate.clone());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let (observed, active, wait, returns) = (
                observed.clone(),
                active.clone(),
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
    f.state.db_pool = pool.clone();
    let result=async {
        let work=witness.begin().await?;
        work.store_scope(async {
            let mut call=Box::pin(caller.call(&f));
            let observed=async {
                while !entered.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(5)).await; }
            };
            tokio::select! {
                result=&mut call => Err::<(),Box<dyn Error>>(format!("{caller:?} returned before actual pool cleanup: {result:?}").into()),
                result=tokio::time::timeout(Duration::from_secs(5),observed) => { result?;drop(call);Ok(()) }
            }
        }).await??;
        let mut completion=tokio::spawn(work.complete());
        let early=tokio::time::timeout(Duration::from_millis(100),&mut completion).await;
        let pending=witness.pending().await?;
        enabled.store(false,Ordering::SeqCst);gate.add_permits(8);
        if early.is_ok() || pending!=1 { return Err(format!("{caller:?} completed witness before actual cleanup").into()); }
        tokio::time::timeout(Duration::from_secs(5),completion).await???;
        assert_eq!(witness.pending().await?,0);
        witness.run(caller.call(&f)).await??;
        if matches!(caller,Caller::Callback) {
            let (id,subject,provenance,revision)=f.owner(&f.request,"owned-upstream").await?;
            assert!(!id.is_nil());assert_eq!(Uuid::parse_str(&subject)?.to_string(),subject);
            assert_eq!((provenance.as_str(),revision),("jit_v2",1));
        }
        Ok(())
    }.await;
    enabled.store(false, Ordering::SeqCst);
    gate.add_permits(8);
    pool.close().await;
    finish(f, witness, result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; signed ID Token callback transaction and actual pool return"]
async fn pg_organizations_upstream_callback_owns_return() -> TestResult {
    owns_return(Caller::Callback).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; current callback connection and actual pool return"]
async fn pg_organizations_upstream_current_connection_owns_return() -> TestResult {
    owns_return(Caller::CurrentConnection).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; upstream authorize connection and actual pool return"]
async fn pg_organizations_upstream_authorize_connection_owns_return() -> TestResult {
    owns_return(Caller::AuthorizeConnection).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; local authentication audit and actual pool return"]
async fn pg_organizations_upstream_local_audit_owns_return() -> TestResult {
    owns_return(Caller::LocalAudit).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; failed session audit and actual pool return"]
async fn pg_organizations_upstream_failure_audit_owns_return() -> TestResult {
    owns_return(Caller::FailureAudit).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; OAuth audit insert and actual second connection return"]
async fn pg_organizations_upstream_oauth_audit_owns_return() -> TestResult {
    owns_return(Caller::OAuthAudit).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; foreign Environment owner must refuse before identity writes"]
async fn pg_organizations_upstream_callback_refuses_foreign_owner() -> TestResult {
    let f = fixture().await?;
    let witness = CallerFixture::new(Uuid::new_v4()).await?;
    let result = async {
        let before = f.snapshot().await?;
        let response = witness
            .run(f.callback(&f.request, "foreign-owner", None))
            .await??;
        if response.status() != StatusCode::SERVICE_UNAVAILABLE
            || response.headers().contains_key(header::SET_COOKIE)
            || f.snapshot().await? != before
        {
            return Err("foreign epoch owner permitted callback identity/session writes".into());
        }
        Ok(())
    }
    .await;
    finish(f, witness, result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; callback identity and audit rollback after owner closure"]
async fn pg_organizations_upstream_callback_refuses_closed_commit() -> TestResult {
    let f = fixture().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
    let result = closed_commit(&f, &witness).await;
    finish(f, witness, result).await
}

async fn closed_commit(f: &Fixture, witness: &CallerFixture) -> TestResult {
    let before = f.snapshot().await?;
    let mut lock = f.pool.begin().await?;
    sqlx::query("LOCK TABLE aegaeon.end_users IN SHARE MODE")
        .execute(&mut *lock)
        .await?;
    let work = witness.begin().await?;
    let owner = work.admission().clone();
    let state = f.state.clone();
    let request = f.request.clone();
    let exchange = f.exchange(&request, "closed-commit", None)?;
    let caller = tokio::spawn(async move {
        let result = work
            .store_scope(persist_bound_upstream_callback(
                &state,
                &request,
                &exchange,
                "closed-upstream",
            ))
            .await;
        (work, result)
    });
    let observed=tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND wait_event_type='Lock' AND query LIKE '%INSERT INTO aegaeon.end_users%')").fetch_one(&f.pool).await?;
            if blocked { return Ok::<_,sqlx::Error>(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await;
    owner.close_until_restart();
    lock.rollback().await?;
    let (work, result) = tokio::time::timeout(Duration::from_secs(5), caller).await??;
    drop(owner);
    let completion = work.complete().await;
    observed??;
    if result.is_ok() || completion.is_ok() || f.snapshot().await? != before {
        return Err("callback identity or audit committed after admission closed".into());
    }
    assert_eq!(witness.pending().await?, 1);
    Ok(())
}
