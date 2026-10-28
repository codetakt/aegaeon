async fn subject_authority_snapshot(
    admin: &sqlx::PgPool,
    environment: Uuid,
) -> Result<serde_json::Value, Box<dyn StdError>> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('namespace',(SELECT to_jsonb(n) FROM aegaeon.subject_ownership_namespaces n WHERE environment_id=$1),'receipt',(SELECT to_jsonb(a) FROM aegaeon.subject_ownership_adoptions a WHERE environment_id=$1),'owners',(SELECT jsonb_agg(to_jsonb(o) ORDER BY owner_id) FROM aegaeon.end_user_identity_owners o WHERE environment_id=$1),'reservations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY subject COLLATE \"C\") FROM aegaeon.end_user_subject_reservations r WHERE environment_id=$1))")
        .bind(environment).fetch_one(admin).await?)
}

async fn full_subject_snapshot(
    runtime: &sqlx::PgPool,
    admin: &sqlx::PgPool,
    environment: Uuid,
) -> Result<serde_json::Value, Box<dyn StdError>> {
    Ok(
        serde_json::json!({"ordinary":subject_format_snapshot(runtime,environment).await?,"authority":subject_authority_snapshot(admin,environment).await?}),
    )
}

async fn assert_subject_owner(
    admin: &sqlx::PgPool,
    environment: Uuid,
    owner: Uuid,
    expected: &[&str],
) -> TestResult {
    let environments: Vec<Uuid> = sqlx::query_scalar(
        "SELECT environment_id FROM aegaeon.end_user_identity_owners WHERE owner_id=$1",
    )
    .bind(owner)
    .fetch_all(admin)
    .await?;
    assert_eq!(environments, vec![environment]);
    let mut actual:Vec<String>=sqlx::query_scalar("SELECT subject FROM aegaeon.end_user_subject_reservations WHERE environment_id=$1 AND owner_id=$2").bind(environment).bind(owner).fetch_all(admin).await?;
    actual.sort();
    let mut expected: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
    expected.sort();
    assert_eq!(actual, expected);
    Ok(())
}

struct SubjectOwnershipFixture {
    runtime: sqlx::PgPool,
    admin: sqlx::PgPool,
    env: RuntimeKeyTestEnvironment,
    app: axum::Router,
    sid: String,
}
impl SubjectOwnershipFixture {
    async fn new() -> Result<Self, Box<dyn StdError>> {
        let runtime = membership_test_pool().await?;
        let admin = crate::web::test_support::test_admin_pool(&runtime).await?;
        let env = setup_runtime_key_test_environment(&runtime).await?;
        let mgmt = test_management_state();
        let sid = mgmt
            .sessions
            .create(env.administrator_id, crate::util::now_unix_epoch_secs()?)
            .ok_or("human session")?;
        let app = super::super::build_router(test_app_state(runtime.clone(), mgmt)?);
        Ok(Self {
            runtime,
            admin,
            env,
            app,
            sid,
        })
    }
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: serde_json::Value,
    ) -> Result<axum::response::Response, Box<dyn StdError>> {
        let is_delete = method == Method::DELETE;
        let mut request = membership_http_request(method, &self.env, path, &self.sid, body)?;
        if is_delete {
            *request.body_mut() = Body::empty();
        }
        Ok(self.app.clone().oneshot(request).await?)
    }
    async fn create(&self, subject: &str) -> Result<Uuid, Box<dyn StdError>> {
        let response = self
            .send(
                Method::POST,
                "users",
                serde_json::json!({"subject":subject}),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        Ok(response_json(response).await?["id"]
            .as_str()
            .ok_or("user id")?
            .parse()?)
    }
    async fn rename(&self, owner: Uuid, subject: &str) -> TestResult {
        let response = self
            .send(
                Method::PATCH,
                &format!("users/{owner}"),
                serde_json::json!({"subject":subject}),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await?["subject"], subject);
        Ok(())
    }
    async fn snapshot(&self) -> Result<serde_json::Value, Box<dyn StdError>> {
        full_subject_snapshot(&self.runtime, &self.admin, self.env.environment_id).await
    }
}

async fn historical_http_conflicts(
    f: &SubjectOwnershipFixture,
    owner: Uuid,
    other: Uuid,
) -> TestResult {
    let current:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1 AND subject='historical-private-subject'")
        .bind(f.env.environment_id).fetch_one(&f.runtime).await?;
    assert_eq!(
        current, 0,
        "conflict must be historical, not live uniqueness"
    );
    for (method, path, body) in [
        (
            Method::POST,
            "users".into(),
            serde_json::json!({"subject":"historical-private-subject"}),
        ),
        (
            Method::POST,
            "users/invitations".into(),
            serde_json::json!({"subject":"historical-private-subject","email":"invite@example.com"}),
        ),
        (
            Method::POST,
            "users/importCsv".into(),
            serde_json::json!({"csv":"subject,email\nprovisional-csv,csv@example.com\nhistorical-private-subject,history@example.com\n"}),
        ),
        (
            Method::PATCH,
            format!("users/{other}"),
            serde_json::json!({"subject":"historical-private-subject","email":"changed@example.com"}),
        ),
    ] {
        let before = f.snapshot().await?;
        let response = f.send(method, &path, body).await?;
        let status = response.status();
        let error = response_json(response).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{error}");
        assert_eq!(error["errorCode"], "conflict");
        assert_eq!(error["message"], "Subject ownership conflict");
        assert!(error.get("details").is_none());
        let text = error.to_string();
        assert!(!text.contains(&owner.to_string()));
        assert!(!text.contains("historical-private-subject"));
        assert_eq!(f.snapshot().await?, before, "{path}");
    }
    Ok(())
}

async fn subject_lifecycle_preserves_history(
    f: &SubjectOwnershipFixture,
    owner: Uuid,
) -> TestResult {
    f.rename(owner, "historical-private-subject").await?;
    let history = subject_authority_snapshot(&f.admin, f.env.environment_id).await?;
    sqlx::query("UPDATE aegaeon.end_users SET status='ACTIVE' WHERE id=$1")
        .bind(owner)
        .execute(&f.runtime)
        .await?;
    for (method, path, status) in [
        (
            Method::POST,
            format!("users/{owner}/suspend"),
            StatusCode::OK,
        ),
        (
            Method::POST,
            format!("users/{owner}/unsuspend"),
            StatusCode::OK,
        ),
        (
            Method::DELETE,
            format!("users/{owner}"),
            StatusCode::NO_CONTENT,
        ),
        (
            Method::POST,
            format!("users/{owner}/restore"),
            StatusCode::OK,
        ),
    ] {
        let response = f.send(method, &path, serde_json::json!({})).await?;
        assert_eq!(response.status(), status, "{path}");
        assert_eq!(
            subject_authority_snapshot(&f.admin, f.env.environment_id).await?,
            history
        );
    }
    let current: (Uuid, String) = sqlx::query_as(
        "SELECT id,subject FROM aegaeon.end_users WHERE id=$1 AND status <> 'DELETED'",
    )
    .bind(owner)
    .fetch_one(&f.runtime)
    .await?;
    assert_eq!(current, (owner, "historical-private-subject".into()));
    Ok(())
}

async fn historical_uuid_and_subject_refuse(f: &SubjectOwnershipFixture) -> TestResult {
    let owner = f.create("physical-historical-subject").await?;
    f.rename(owner, "physical-current-subject").await?;
    sqlx::query("DELETE FROM aegaeon.end_users WHERE id=$1")
        .bind(owner)
        .execute(&f.runtime)
        .await?;
    let before = f.snapshot().await?;
    for (id, subject, constraint) in [
        (
            owner,
            "fresh-uuid-attempt",
            "end_users_historical_uuid_reuse",
        ),
        (
            Uuid::new_v4(),
            "physical-historical-subject",
            "end_users_subject_owner_conflict",
        ),
    ] {
        let result=sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')")
            .bind(id).bind(f.env.environment_id).bind(subject).execute(&f.runtime).await;
        let error = result.err().ok_or("historical identity reused")?;
        let sqlx::Error::Database(error) = error else {
            return Err("expected named database constraint".into());
        };
        assert_eq!(error.code().as_deref(), Some("23505"));
        assert_eq!(error.constraint(), Some(constraint));
        assert_eq!(f.snapshot().await?, before);
    }
    assert_subject_owner(
        &f.admin,
        f.env.environment_id,
        owner,
        &["physical-historical-subject", "physical-current-subject"],
    )
    .await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and AEGAEON_TEST_ADMIN_DATABASE_URL observations"]
async fn permanent_subject_management_history_conflicts_and_lifecycle_are_atomic() -> TestResult {
    let f = SubjectOwnershipFixture::new().await?;
    let owner = f.create("historical-private-subject").await?;
    f.rename(owner, "renamed-current-subject").await?;
    let other = f.create("unrelated-current-subject").await?;
    assert_subject_owner(
        &f.admin,
        f.env.environment_id,
        owner,
        &["historical-private-subject", "renamed-current-subject"],
    )
    .await?;
    historical_http_conflicts(&f, owner, other).await?;
    subject_lifecycle_preserves_history(&f, owner).await?;
    historical_uuid_and_subject_refuse(&f).await
}
