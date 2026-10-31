use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; expiry during actual primary receipt append"]
async fn pg_organizations_creation_upstream_expiry_before_commit() -> TestResult {
    let (f, witness) = fixture().await?;
    let admin = test_admin_pool(&f.pool).await?;
    let name = format!("upstream_expiry_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id='{}'::uuid THEN PERFORM pg_sleep(3); END IF; RETURN NEW; END $$; CREATE TRIGGER {name} AFTER INSERT ON aegaeon.organization_creation_receipts FOR EACH ROW EXECUTE FUNCTION aegaeon.{name}()", f.env.environment_id))
        .execute(&admin).await?;
    let first = run(&witness, async {
        let mut request = f.request.clone();
        request.expires_at = std::time::SystemTime::now() + Duration::from_secs(2);
        let exchange = f.exchange(&request, "final-expiry", None)?;
        let initial = f.snapshot().await?;
        let owner = async_store::task_owner()?.ok_or("actual work")?;
        let label = owner.store_label()?.ok_or("work label")?.to_owned();
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND wait_event='PgSleep' AND query LIKE '%organization_creation_record_v1%')")
                    .bind(&label).fetch_one(&admin).await?;
                if waiting { return Ok::<_, sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let callback = persist_bound_upstream_callback(&f.state, &request, &exchange, "expiry-before-commit");
        let (observed, response) = tokio::join!(observed, callback);
        observed??;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert_eq!(f.snapshot().await?, initial);
        Ok(())
    }).await;
    let removed = sqlx::raw_sql(&format!("DROP TRIGGER {name} ON aegaeon.organization_creation_receipts; DROP FUNCTION aegaeon.{name}()"))
        .execute(&admin).await;
    let result = async {
        first?;
        removed?;
        let before = witness.creation_rows("upstream").await?;
        assert_eq!(before.len(), 1);
        assert_eq!((&*before[0].2, before[0].3), ("retryable", 1));
        run(&witness, async {
            let subject = f
                .success_subject(f.callback(&f.request, "final-expiry", None).await?)
                .await?;
            assert_eq!(subject, before[0].1);
            assert_eq!(
                witness.creation_rows("upstream").await?,
                vec![(before[0].0, subject, "committed".into(), 2)]
            );
            Ok(())
        })
        .await
    }
    .await;
    admin.close().await;
    finish(f, witness, result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; current connection changes after authenticated preflight"]
async fn pg_organizations_creation_upstream_revocation_after_preflight() -> TestResult {
    let (f, witness) = fixture().await?;
    let admin = test_admin_pool(&f.pool).await?;
    let result = async {
        let mut barrier = witness.history_append_barrier().await?;
        let refused = run(&witness, async {
            let controller = async {
                let observed = witness.wait_for_creation_prepare().await;
                let changed = if observed.is_ok() {
                    sqlx::query("UPDATE aegaeon.connections SET client_id='changed-after-preflight' WHERE id=$1")
                        .bind(f.request.context.connection_id).execute(&admin).await.map(|r| r.rows_affected())
                } else { Ok(0) };
                let released = sqlx::query("ROLLBACK").execute(&mut barrier).await;
                let closed = sqlx::Connection::close(barrier).await;
                observed?;
                assert_eq!(changed?, 1);
                released?;
                closed?;
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let (observed, response) = tokio::join!(controller, f.rejected(&f.request, "revoked", None));
            observed?;
            response
        }).await;
        let restored = sqlx::query("UPDATE aegaeon.connections SET client_id=$2 WHERE id=$1")
            .bind(f.request.context.connection_id).bind(&f.request.client_id).execute(&admin).await;
        refused?;
        assert_eq!(restored?.rows_affected(), 1);
        let before = witness.creation_rows("upstream").await?;
        assert_eq!(before.len(), 1);
        assert_eq!((&*before[0].2, before[0].3), ("retryable", 1));
        run(&witness, async {
            let subject = f.success_subject(f.callback(&f.request, "revoked", None).await?).await?;
            assert_eq!(subject, before[0].1);
            assert_eq!(witness.creation_rows("upstream").await?, vec![(before[0].0, subject, "committed".into(), 2)]);
            Ok(())
        }).await
    }.await;
    admin.close().await;
    finish(f, witness, result).await
}
