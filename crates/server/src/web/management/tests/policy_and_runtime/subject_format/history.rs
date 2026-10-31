use crate::organizations::witness::tests::caller_fixture::CallerFixture;

async fn history_test(future: impl std::future::Future<Output = TestResult>) -> TestResult {
    use std::{
        future::poll_fn,
        panic::{catch_unwind, AssertUnwindSafe},
        task::Poll,
    };
    let mut future = Box::pin(future);
    poll_fn(
        |context| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(result) => result,
            Err(_) => Poll::Ready(Err(std::io::Error::other(
                "subject history test panicked; assertion retained",
            )
            .into())),
        },
    )
    .await
}

struct RenameHistoryFixture {
    user: SubjectOwnershipFixture,
    witness: CallerFixture,
    owner: Uuid,
    historical_owner: Uuid,
}
impl RenameHistoryFixture {
    async fn new() -> Result<Self, Box<dyn StdError>> {
        let user = SubjectOwnershipFixture::new().await?;
        let owner = user.create("original").await?;
        let historical_owner = Uuid::new_v4();
        let witness = CallerFixture::with_history(
            user.env.environment_id,
            &[
                (owner, vec!["original"]),
                (historical_owner, vec!["retained-only"]),
            ],
        )
        .await?;
        Ok(Self {
            user,
            witness,
            owner,
            historical_owner,
        })
    }

    async fn rename(&self, subject: &str) -> Result<axum::response::Response, Box<dyn StdError>> {
        Ok(self
            .witness
            .run(self.user.send(
                Method::PATCH,
                &format!("users/{}", self.owner),
                serde_json::json!({"subject":subject}),
            ))
            .await??)
    }

    async fn finish(self, result: TestResult) -> TestResult {
        let witness = self.witness.finish().await;
        let users =
            cleanup_subject_format_users(&self.user.runtime, self.user.env.environment_id).await;
        let cleanup =
            cleanup_runtime_key_test_environment(&self.user.runtime, &self.user.env).await;
        witness?;
        users?;
        finish_runtime_key_pg_test(result, cleanup)
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; HTTP subject rename retains exact independent history"]
async fn pg_organizations_subject_rename_history_normal_replay() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let result: TestResult = history_test(async {
        let maximum = "x".repeat(255);
        for subject in [
            "Case",
            "case",
            "A\tB\u{7f}",
            maximum.as_str(),
            maximum.as_str(),
        ] {
            let response = f.rename(subject).await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response_json(response).await?["subject"], subject);
        }
        let mut expected = vec![
            "original".to_owned(),
            "Case".to_owned(),
            "case".to_owned(),
            "A\tB\u{7f}".to_owned(),
            maximum,
        ];
        expected.sort();
        assert_eq!(f.witness.retained_subjects(f.owner).await?, expected);
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; independent-only historical conflict refuses HTTP rename"]
async fn pg_organizations_subject_rename_history_conflict() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let result: TestResult = history_test(async {
        let before = f.user.snapshot().await?;
        let response = f.rename("retained-only").await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let error = response_json(response).await?;
        assert_eq!(error["message"], "Subject ownership conflict");
        assert!(!error.to_string().contains("retained-only"));
        assert!(!error.to_string().contains(&f.historical_owner.to_string()));
        assert_eq!(f.user.snapshot().await?, before);
        assert_eq!(
            f.witness.retained_subjects(f.owner).await?,
            vec!["original"]
        );
        assert_eq!(
            f.witness.retained_subjects(f.historical_owner).await?,
            vec!["retained-only"]
        );
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; primary audit failure preserves reservation and exact retry"]
async fn pg_organizations_subject_rename_history_primary_failure() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let name = format!("test_subject_history_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id='{}'::uuid AND NEW.event_type='management.user.updated.v1' THEN RAISE EXCEPTION 'injected subject audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.{name}()", f.user.env.environment_id))
        .execute(&f.user.admin).await?;
    let result: TestResult = history_test(async {
        let before = f.user.snapshot().await?;
        let response = f.rename("recoverable").await?;
        assert!(!response.status().is_success());
        assert_eq!(f.user.snapshot().await?, before);
        assert_eq!(
            f.witness.retained_subjects(f.owner).await?,
            vec!["original", "recoverable"]
        );
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    let cleanup = sqlx::raw_sql(&format!(
        "DROP TRIGGER {name} ON aegaeon.audit_events; DROP FUNCTION aegaeon.{name}()"
    ))
    .execute(&f.user.admin)
    .await;
    let result: TestResult = history_test(async {
        result?;
        cleanup?;
        let response = f.rename("recoverable").await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await?["subject"], "recoverable");
        assert_eq!(
            f.witness.retained_subjects(f.owner).await?,
            vec!["original", "recoverable"]
        );
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; no invalid-scope or missing-history fallback for rename"]
async fn pg_organizations_subject_rename_history_scope_and_missing() -> TestResult {
    let f = SubjectOwnershipFixture::new().await?;
    let owner = f.create("original").await?;
    let path = format!("users/{owner}");
    let before = f.snapshot().await?;
    let result: TestResult = history_test(async {
        let bare = crate::organizations::request_work::Admission::isolated_for_test()?;
        let response = bare
            .store_scope(f.send(Method::PATCH, &path, serde_json::json!({"subject":"bare"})))
            .await??;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(f.snapshot().await?, before);
        for environment in [Uuid::new_v4(), f.env.environment_id] {
            let witness = CallerFixture::with_history(environment, &[]).await?;
            let result: TestResult = history_test(async {
                let response = witness
                    .run(f.send(
                        Method::PATCH,
                        &path,
                        serde_json::json!({"subject":"missing"}),
                    ))
                    .await??;
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(f.snapshot().await?, before);
                assert_eq!(witness.pending().await?, 0);
                Ok(())
            })
            .await;
            witness.finish().await?;
            result?;
        }
        Ok(())
    })
    .await;
    cleanup_subject_format_users(&f.runtime, f.env.environment_id).await?;
    finish_runtime_key_pg_test(
        result,
        cleanup_runtime_key_test_environment(&f.runtime, &f.env).await,
    )
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; revoked administrator cannot reserve or rename a subject"]
async fn pg_organizations_subject_rename_history_authority() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let result: TestResult = history_test(async {
        sqlx::query("UPDATE aegaeon.team_memberships SET role='AUDITOR' WHERE team_id=$1 AND administrator_id=$2")
            .bind(f.user.env.team_id).bind(f.user.env.administrator_id).execute(&f.user.runtime).await?;
        let before = f.user.snapshot().await?;
        let response = f.rename("forbidden").await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(f.user.snapshot().await?, before);
        assert_eq!(f.witness.retained_subjects(f.owner).await?, vec!["original"]);
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    }).await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; role revocation after reservation preflight must block the write"]
async fn pg_organizations_subject_rename_history_rechecks_authority() -> TestResult {
    use sqlx::Connection;
    let mut f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let before = f.user.snapshot().await?;
        let mut barrier = f.witness.history_append_barrier().await?;
        let request = membership_http_request(Method::PATCH, &f.user.env,
            &format!("users/{}", f.owner), &f.user.sid, serde_json::json!({"subject":"concurrent"}))?;
        let app = f.user.app.clone();
        let work = f.witness.begin().await?;
        let execution = tokio::spawn(work.execute(async move { app.oneshot(request).await }));
        let revoked: TestResult = async {
            f.witness.wait_for_history_append().await?;
            // The read/lock-only authorization transaction must already have
            // released its role lock. Revocation commits before reservation ends.
            tokio::time::timeout(std::time::Duration::from_secs(1),
                sqlx::query("UPDATE aegaeon.team_memberships SET role='AUDITOR' WHERE team_id=$1 AND administrator_id=$2")
                    .bind(f.user.env.team_id).bind(f.user.env.administrator_id).execute(&f.user.runtime)).await??;
            Ok(())
        }.await;
        let release = sqlx::query("ROLLBACK").execute(&mut barrier).await;
        let close = barrier.close().await;
        let response = execution.await???;
        revoked?;
        release?;
        close?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(f.user.snapshot().await?, before);
        assert_eq!(f.witness.retained_subjects(f.owner).await?, vec!["concurrent", "original"]);
        assert_eq!(f.witness.pending().await?, 0);
        sqlx::query("UPDATE aegaeon.team_memberships SET role='OWNER' WHERE team_id=$1 AND administrator_id=$2")
            .bind(f.user.env.team_id).bind(f.user.env.administrator_id).execute(&f.user.runtime).await?;
        assert_eq!(f.rename("concurrent").await?.status(), StatusCode::OK);
        Ok(())
    }).await;
    f.finish(result).await
}
