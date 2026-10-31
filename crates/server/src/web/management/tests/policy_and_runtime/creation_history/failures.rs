async fn creation_primary_wait(pool: &sqlx::PgPool, label: &str) -> Result<i32, Box<dyn StdError>> {
    Ok(tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let pid:Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '%organization_creation_record_v1%'")
                .bind(label).fetch_optional(pool).await?;
            if let Some(pid) = pid { return Ok::<_, sqlx::Error>(pid); }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }).await??)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; same-work creation serialization spans the primary transaction and independent finish"]
async fn pg_organizations_creation_management_concurrent_same_work() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let key = Uuid::new_v4().to_string();
        let mut barrier = f.user.admin.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.organization_creation_receipts IN SHARE MODE").execute(&mut *barrier).await?;
        let work = f.witness.begin().await?;
        let label = work.admission().store_label()?.ok_or("work label")?.to_owned();
        let owner = work.admission().clone();
        let app = f.user.app.clone();
        let request = creation_http_request(&f, &[&key], "concurrent")?;
        let first = tokio::spawn(async move { owner.store_scope(app.oneshot(request)).await });
        let observed = creation_primary_wait(&f.user.admin, &label).await;
        let second = tokio::time::timeout(std::time::Duration::from_secs(1), work.store_scope(
            f.user.app.clone().oneshot(creation_http_request(&f, &[&key], "concurrent")?)
        )).await;
        // Release and join even when the observation or competing response failed.
        let release = barrier.rollback().await;
        let first = first.await;
        observed?; release?;
        assert_eq!(second???.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(first???.status(), StatusCode::CREATED);
        work.admission().ensure_open()?;
        assert_eq!(work.complete().await?.pending, 0);
        let (id, state, attempt) = f.witness.retained_creation("concurrent").await?;
        assert_eq!((state, attempt), ("committed".into(), 1));
        assert_eq!(creation_request(&f, &[&key], "concurrent").await?.status(), StatusCode::OK);
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND target_id=$2 AND event_type='management.user.created.v1'")
            .bind(f.user.env.environment_id).bind(id.to_string()).fetch_one(&f.user.runtime).await?;
        assert_eq!(count, 1);
        Ok(())
    }).await;
    f.finish(result).await
}

#[derive(Clone, Copy)]
enum CreationInterruption {
    CancelPrimary,
    DisconnectPrimary,
    DisconnectFinish,
}

async fn creation_interrupted(mode: CreationInterruption) -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let key = Uuid::new_v4().to_string();
        let before = f.user.snapshot().await?;
        let mut barrier = f.user.admin.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.organization_creation_receipts IN SHARE MODE").execute(&mut *barrier).await?;
        let work = f.witness.begin().await?;
        let closure = work.admission().closure_probe_for_test();
        let label = work.admission().store_label()?.ok_or("work label")?.to_owned();
        let owner = work.admission().clone();
        let app = f.user.app.clone();
        let request = creation_http_request(&f, &[&key], "interrupted")?;
        // Deliberately cancel the actual operation, not merely execute()'s waiter.
        let execution = tokio::spawn(async move { owner.store_scope(app.oneshot(request)).await });
        let observed = creation_primary_wait(&f.user.admin, &label).await;
        let pid = match observed {
            Ok(pid) => pid,
            Err(error) => { execution.abort(); let _ = execution.await; barrier.rollback().await?; return Err(error); }
        };
        if matches!(mode, CreationInterruption::DisconnectFinish) {
            let mut independent = f.witness.creation_finish_barrier().await?;
            barrier.rollback().await?;
            let cut = f.witness.disconnect_creation_finish().await;
            let release = sqlx::query("ROLLBACK").execute(&mut independent).await;
            let close = sqlx::Connection::close(independent).await;
            cut?; release?; close?;
        } else {
            if matches!(mode, CreationInterruption::CancelPrimary) {
                execution.abort();
            } else {
                sqlx::query("SELECT pg_terminate_backend($1)").bind(pid).execute(&f.user.admin).await?;
            }
            barrier.rollback().await?;
        }
        let response = execution.await;
        if matches!(mode, CreationInterruption::CancelPrimary) {
            assert!(response.is_err_and(|error| error.is_cancelled()));
        } else {
            assert!(response?.is_err(), "closed store scope must refuse its result");
        }
        assert!(closure.is_closed());
        assert!(work.complete().await.is_err());
        assert_eq!(f.witness.pending().await?, 1);
        let (id, state, attempt) = f.witness.retained_creation("interrupted").await?;
        assert_eq!((state, attempt), ("reserved".into(), 1));
        let committed = matches!(mode, CreationInterruption::DisconnectFinish);
        let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.end_users WHERE id=$1),(SELECT count(*) FROM aegaeon.organization_creation_receipts WHERE owner_id=$1)")
            .bind(id).fetch_one(&f.user.runtime).await?;
        assert_eq!(counts, (i64::from(committed), i64::from(committed)));
        if !committed { assert_eq!(f.user.snapshot().await?, before); }
        let snapshot = f.user.snapshot().await?;
        assert!(!creation_request(&f, &[&key], "interrupted").await?.status().is_success());
        assert_eq!(f.user.snapshot().await?, snapshot);
        assert_eq!(f.witness.pending().await?, 1);
        Ok(())
    }).await;
    f.finish(result).await
}

macro_rules! creation_interruption_test {
    ($name:ident, $mode:ident) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL; actual creation failure retains pending operation and original owner"]
        async fn $name() -> TestResult { creation_interrupted(CreationInterruption::$mode).await }
    };
}
creation_interruption_test!(
    pg_organizations_creation_management_cancel_primary,
    CancelPrimary
);
creation_interruption_test!(
    pg_organizations_creation_management_disconnect_primary,
    DisconnectPrimary
);
creation_interruption_test!(
    pg_organizations_creation_management_disconnect_finish,
    DisconnectFinish
);
