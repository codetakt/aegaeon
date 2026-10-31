use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use std::future::Future;
mod currentness;
mod settlement;

async fn fixture() -> TestResult<(Fixture, CallerFixture)> {
    let mut f = Fixture::new().await?;
    f.prepare_scoped().await?;
    let witness = CallerFixture::with_history(f.env.environment_id, &[]).await?;
    Ok((f, witness))
}
async fn run<T>(
    witness: &CallerFixture,
    future: impl Future<Output = TestResult<T>>,
) -> TestResult<T> {
    let work = witness.begin().await?;
    let result = {
        let mut running = Box::pin(work.store_scope(future));
        std::future::poll_fn(|cx| {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                running.as_mut().poll(cx)
            })) {
                Ok(value) => value.map(Ok),
                Err(_) => std::task::Poll::Ready(Err("upstream fixture assertion failed")),
            }
        })
        .await
    };
    let completion = work.complete().await;
    let value = result??;
    completion?;
    value
}
async fn finish(f: Fixture, witness: CallerFixture, result: TestResult) -> TestResult {
    let supplier = witness.finish().await.map_err(Into::into);
    let cleanup = f.cleanup().await;
    f.state.db_pool.close().await;
    f.pool.close().await;
    result.and(supplier).and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; signed upstream proof and retained creation"]
async fn pg_organizations_creation_upstream_repeat_plain_uuid_and_deletion() -> TestResult {
    let (f, witness) = fixture().await?;
    let result = run(&witness, async {
        let now=now_epoch_secs()?;
        let exchange=f.signed_exchange(&f.request,json!({"iss":f.request.issuer,"sub":"external-id","aud":"client","iat":now,"exp":now+3600,"auth_time":now-30,"nonce":"nonce","name":"組織の利用者","email":"first@example.test","email_verified":true}))?;
        let response=persist_bound_upstream_callback(&f.state,&f.request,&exchange,"retained-unicode-profile").await;
        let subject = f.success_subject(response).await?;
        let owner = f.owner(&f.request, "external-id").await?;
        assert_eq!(subject, owner.0.to_string());
        let name:Option<String>=sqlx::query_scalar("SELECT display_name FROM aegaeon.end_user_profiles WHERE end_user_id=$1").bind(owner.0).fetch_one(&f.pool).await?;
        assert_eq!(name.as_deref(),Some("組織の利用者"));
        let retained = witness.creation_rows("upstream").await?;
        assert_eq!(
            retained,
            vec![(owner.0, subject.clone(), "committed".into(), 1)]
        );
        let mut request = f.request.clone();
        request.state = "fresh-browser-request".into();
        assert_eq!(
            f.success_subject(
                f.callback(&request, "external-id", Some("changed@example.test"))
                    .await?
            )
            .await?,
            subject
        );
        assert_eq!(witness.creation_rows("upstream").await?, retained);
        sqlx::query("UPDATE aegaeon.end_users SET status='DELETED' WHERE id=$1")
            .bind(owner.0)
            .execute(&f.pool)
            .await?;
        f.rejected(&request, "external-id", None).await?;
        assert_eq!(witness.creation_rows("upstream").await?, retained);
        Ok(())
    })
    .await;
    finish(f, witness, result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; scoped current policy and exact Environment"]
async fn pg_organizations_creation_upstream_preflight_refusals() -> TestResult {
    let (f, witness) = fixture().await?;
    let result = run(&witness, async {
        for change in 0..4 {
            let mut request = f.request.clone();
            match change {
                0 => request.context.configuration_version_id = Uuid::new_v4(),
                1 => request.context.connection_id = Uuid::new_v4(),
                2 => request.expires_at = std::time::UNIX_EPOCH,
                _ => request.jit_provisioning_policy = None,
            }
            f.rejected(&request, "refused", None).await?;
        }
        assert!(witness.creation_rows("upstream").await?.is_empty());
        f.success_subject(f.callback(&f.request, "allowed", None).await?)
            .await?;
        Ok(())
    })
    .await;
    finish(f, witness, result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; exact issuer and Unicode subject binding"]
async fn pg_organizations_creation_upstream_exact_identity_and_payload() -> TestResult {
    let (f, witness) = fixture().await?;
    let result = run(&witness, async {
        // Preserve the existing OIDC subject grammar; arbitrary UTF-8 belongs
        // to Organizations external IDs and profile fields, not ID Token sub.
        assert!(f.exchange(&f.request, "é", None).is_err());
        let mut owners = std::collections::BTreeSet::new();
        for subject in ["Case", "case", "%C3%A9", "e%CC%81", "org:ASCII/id"] {
            let user = f
                .success_subject(f.callback(&f.request, subject, None).await?)
                .await?;
            assert!(owners.insert(user));
        }
        let request = f.with_issuer("https://issuer.example:443").await?;
        assert!(owners.insert(
            f.success_subject(f.callback(&request, "Case", None).await?)
                .await?
        ));
        assert_eq!(witness.creation_rows("upstream").await?.len(), 6);
        Ok(())
    })
    .await;
    finish(f, witness, result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual callback audit failure and owner reuse"]
async fn pg_organizations_creation_upstream_rollback_reuses_owner() -> TestResult {
    let (f, witness) = fixture().await?;
    let admin = test_admin_pool(&f.pool).await?;
    let name = format!("upstream_creation_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test callback refusal'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW WHEN (NEW.environment_id='{}'::uuid AND NEW.event_type='upstream_auth') EXECUTE FUNCTION aegaeon.{name}();",f.env.environment_id)).execute(&admin).await?;
    let first = run(&witness, async {
        f.rejected(&f.request, "rollback", Some("retry@example.test"))
            .await
    })
    .await;
    let removed = sqlx::raw_sql(&format!(
        "DROP TRIGGER {name} ON aegaeon.audit_events; DROP FUNCTION aegaeon.{name}()"
    ))
    .execute(&admin)
    .await;
    let result = async {
        first?;
        removed?;
        let before = witness.creation_rows("upstream").await?;
        assert_eq!(before.len(), 1);
        assert_eq!((&before[0].2, before[0].3), (&"retryable".to_string(), 1));
        run(&witness, async {
            f.rejected(&f.request, "rollback", Some("different@example.test"))
                .await?;
            assert_eq!(witness.creation_rows("upstream").await?, before);
            // A new browser request retains the failed operation and owner.
            let mut request = f.request.clone();
            request.state = "retry-browser".into();
            let subject = f
                .success_subject(
                    f.callback(&request, "rollback", Some("retry@example.test"))
                        .await?,
                )
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
