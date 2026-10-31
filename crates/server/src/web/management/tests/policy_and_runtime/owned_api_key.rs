// Actual key authentication SQL, cancellation, revocation and lost transport.
#[derive(Clone, Copy)]
enum KeyInterruption {
    LookupCancel,
    TouchCancel,
    TouchDisconnect,
    RevokeWhileWaiting,
}

async fn management_key_interruption(mode: KeyInterruption) -> TestResult {
    let f = RenameHistoryFixture::new().await?;
    let service = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.administrators(id,email,password_hash,kind) VALUES($1,$2,'disabled-service-login','SERVICE')")
        .bind(service).bind(format!("service-{service}@example.com")).execute(&f.user.runtime).await?;
    let result = history_test(async {
        let prefix = format!("aeg_{}", &Uuid::new_v4().simple().to_string()[..8]);
        let secret = format!("{prefix}_{}", Uuid::new_v4().simple());
        let key: Uuid = sqlx::query_scalar("INSERT INTO aegaeon.api_keys(team_id,service_administrator_id,name,key_prefix,key_hash) VALUES($1,$2,'owned',$3,$4) RETURNING id")
            .bind(f.user.env.team_id).bind(service).bind(&prefix)
            .bind(super::sha256_array(secret.as_bytes()).as_slice()).fetch_one(&f.user.runtime).await?;
        sqlx::query("INSERT INTO aegaeon.api_key_capabilities(api_key_id,capability) VALUES($1,'READ')")
            .bind(key).execute(&f.user.runtime).await?;
        let state = test_app_state(f.user.runtime.clone(), test_management_state())?;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {secret}").parse()?);
        let mut barrier = f.user.admin.begin().await?;
        if matches!(mode, KeyInterruption::LookupCancel) {
            sqlx::query("LOCK TABLE aegaeon.api_keys IN ACCESS EXCLUSIVE MODE")
                .execute(&mut *barrier).await?;
        } else {
            sqlx::query("SELECT id FROM aegaeon.api_keys WHERE id=$1 FOR UPDATE")
                .bind(key).fetch_one(&mut *barrier).await?;
        }
        let work = f.witness.begin().await?;
        let label = work.admission().store_label()?.ok_or("missing key work label")?.to_owned();
        let closure = work.admission().closure_probe_for_test();
        let waiter = tokio::spawn(work.execute(async move {
            super::require_management_session_async(&state, &headers, "owned-key").await
        }));
        let observed = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'")
                    .bind(&label).fetch_optional(&f.user.admin).await?;
                if let Some(pid) = pid { return Ok::<_, sqlx::Error>(pid); }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }).await;
        let pid = match observed {
            Ok(Ok(pid)) => pid,
            failed => {
                waiter.abort();
                let _cancelled = waiter.await;
                barrier.rollback().await?;
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    loop {
                        if f.witness.pending().await? == 0 { return Ok::<(), anyhow::Error>(()); }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }).await??;
                failed??;
                return Err("missing observed key work".into());
            }
        };
        let cancelled = matches!(mode, KeyInterruption::LookupCancel | KeyInterruption::TouchCancel);
        let action = if matches!(mode, KeyInterruption::TouchDisconnect) {
            sqlx::query("SELECT pg_terminate_backend($1)").bind(pid).execute(&f.user.admin).await.map(|_| ())
        } else if matches!(mode, KeyInterruption::RevokeWhileWaiting) {
            sqlx::query("UPDATE aegaeon.api_keys SET status='REVOKED',revoked_at=now(),revoked_by_administrator_id=$2 WHERE id=$1")
                .bind(key).bind(f.user.env.administrator_id).execute(&mut *barrier).await.map(|_| ())
        } else {
            waiter.abort();
            Ok(())
        };
        let pending = f.witness.pending().await;
        let release = if matches!(mode, KeyInterruption::RevokeWhileWaiting) {
            barrier.commit().await
        } else {
            barrier.rollback().await
        };
        action?;
        release?;
        assert_eq!(pending?, 1);
        let result = waiter.await;
        if cancelled {
            assert!(result.is_err_and(|error| error.is_cancelled()));
        } else if matches!(mode, KeyInterruption::TouchDisconnect) {
            assert!(result?.is_err(), "lost primary transport must not complete durable work");
            assert!(closure.is_closed());
            assert_eq!(f.witness.pending().await?, 1);
        } else {
            assert_eq!(result??.err().ok_or("revoked key authenticated")?.status(), StatusCode::UNAUTHORIZED);
        }
        if !matches!(mode, KeyInterruption::TouchDisconnect) {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if f.witness.pending().await? == 0 { return Ok::<(), anyhow::Error>(()); }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }).await??;
            assert!(!closure.is_closed());
        }
        let touched: bool = sqlx::query_scalar("SELECT last_used_at IS NOT NULL FROM aegaeon.api_keys WHERE id=$1")
            .bind(key).fetch_one(&f.user.runtime).await?;
        assert_eq!(touched, cancelled);
        Ok(())
    }).await;
    let cleanup = async {
        sqlx::query("DELETE FROM aegaeon.api_keys WHERE service_administrator_id=$1")
            .bind(service)
            .execute(&f.user.runtime)
            .await?;
        sqlx::query("DELETE FROM aegaeon.administrators WHERE id=$1")
            .bind(service)
            .execute(&f.user.runtime)
            .await?;
        Ok::<(), sqlx::Error>(())
    }
    .await;
    f.finish(result.and(cleanup.map_err(Into::into))).await
}

macro_rules! key_owner_test {
    ($name:ident, $mode:ident) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL; actual key SQL ownership and current status under interruption"]
        async fn $name() -> TestResult { management_key_interruption(KeyInterruption::$mode).await }
    };
}
key_owner_test!(pg_organizations_management_key_lookup_cancel, LookupCancel);
key_owner_test!(pg_organizations_management_key_touch_cancel, TouchCancel);
key_owner_test!(
    pg_organizations_management_key_touch_disconnect,
    TouchDisconnect
);
key_owner_test!(
    pg_organizations_management_key_revoked_while_waiting,
    RevokeWhileWaiting
);
