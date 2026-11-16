//! Mounted discovery cancellation preserves owned work and one-use authority.
use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use std::{future::Future, time::Duration};

mod postgres;
mod projection;
use postgres::PgGate;
use projection::{evaluate, projection, same_projection};

async fn scoped<T>(
    witness: &CallerFixture,
    future: impl Future<Output = TestResult<T>>,
) -> TestResult<T> {
    witness.run(future).await?
}

async fn action(
    state: &AppState,
    sid: &str,
    uri: &str,
    boundary: &str,
    token: Option<&str>,
) -> TestResult<(StatusCode, String)> {
    if boundary == "picker" {
        page(state, sid, uri, None).await
    } else {
        page(
            state,
            sid,
            "/auth/consent",
            Some(&[
                ("transaction", token.ok_or("continuation missing")?),
                (
                    "decision",
                    if boundary == "selection" {
                        "select:0"
                    } else {
                        "approve"
                    },
                ),
            ]),
        )
        .await
    }
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_picker_cancel_preserves_owned_work() -> TestResult {
    cancelled("picker").await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_selection_cancel_preserves_owned_work() -> TestResult
{
    cancelled("selection").await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_approval_cancel_preserves_owned_work() -> TestResult {
    cancelled("approval").await
}

async fn cancelled(boundary: &str) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let witness = CallerFixture::with_observed_stores(
        state.environment_id,
        state.db_pool.connect_options().as_ref().clone(),
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?,
    )
    .await?;
    let result = exercise(&f, &state, &witness, boundary).await;
    let observed = witness
        .finish()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
    let closed = fixture::finish(&state).await;
    f.cleanup(result.and(observed).and(closed)).await
}

async fn exercise(
    f: &Fixture,
    state: &AppState,
    witness: &CallerFixture,
    boundary: &str,
) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let sid = scoped(
        witness,
        session(state, format!("organization-user-{}", f.users[1])),
    )
    .await?;
    let uri = selector_uri(state, &key)?;
    let token = if boundary == "picker" {
        None
    } else {
        Some(
            scoped(
                witness,
                runtime::pending(state, &sid, &uri, boundary == "approval"),
            )
            .await?,
        )
    };
    let before = projection(f, state, witness).await?;
    let mut gate = PgGate::create(f, state, boundary, token.as_deref()).await?;
    let target = gate.target_consent.clone();
    let browser_before = crate::web::browser_authorization_admission::available_for_test();
    let work = witness.begin().await?;
    let capacity = work.admission().closure_probe_for_test();
    let dropped = work
        .store_scope(async {
            let mut response = Box::pin(action(state, &sid, &uri, boundary, token.as_deref()));
            let reached = tokio::select! {
                _ = &mut response => Err("HTTP completed before actual PostgreSQL wait".into()),
                result = gate.reached(f, boundary) => result,
            };
            // Drop only the response future; keep the durable request owner alive.
            drop(response);
            reached
        })
        .await;
    let mut completion = Box::pin(work.complete());
    let early_completion = if dropped.as_ref().is_ok_and(|r| r.is_ok()) {
        tokio::time::timeout(Duration::from_millis(25), &mut completion)
            .await
            .ok()
    } else {
        None
    };
    let retained = dropped.as_ref().is_ok_and(|r| r.is_ok()) && early_completion.is_none();
    let browser_retained =
        crate::web::browser_authorization_admission::available_for_test() + 1 == browser_before;
    let pid = gate.route_pid;
    // Release the real lock even when the observation failed. Then drain before
    // evaluating assertions, so a failure cannot leave deliberate store work.
    let released = gate.transaction.rollback().await;
    let completed = match early_completion {
        Some(result) => Ok(result),
        None => tokio::time::timeout(Duration::from_secs(35), &mut completion).await,
    };
    dropped??;
    released?;
    if completed??.pending != 0
        || !retained
        || !browser_retained
        || capacity.is_closed()
        || capacity.available_permits() != 1
        || crate::web::browser_authorization_admission::available_for_test() != browser_before
    {
        return Err("cancelled browser work lost ownership or did not recover capacity".into());
    }
    if let Some(pid) = pid {
        let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND (state='active' OR xact_start IS NOT NULL))")
            .bind(pid).fetch_one(&f.pool).await?;
        if live {
            return Err("target PostgreSQL work remains after completion".into());
        }
    }
    let after = projection(f, state, witness).await?;
    evaluate(&before, &after, boundary, target.as_deref(), state, f)?;
    if boundary != "picker" {
        let (status, body) = scoped(
            witness,
            action(state, &sid, &uri, boundary, token.as_deref()),
        )
        .await?;
        if status != StatusCode::BAD_REQUEST
            || serde_json::from_str::<Value>(&body)?["error"] != "invalid_request"
        {
            return Err("consumed continuation replay was accepted".into());
        }
        same_projection(&after, &projection(f, state, witness).await?)?;
    }
    let fresh = scoped(
        witness,
        runtime::pending(state, &sid, &uri, boundary != "picker"),
    )
    .await?;
    if boundary == "approval" {
        let (status, body) =
            scoped(witness, action(state, &sid, &uri, "approval", Some(&fresh))).await?;
        if status != StatusCode::OK || code(&body, &state.issuer).is_err() {
            return Err("fresh authorization recovery failed".into());
        }
    }
    Ok(())
}
