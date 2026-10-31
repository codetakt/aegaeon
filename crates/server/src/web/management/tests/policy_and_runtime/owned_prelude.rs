// Actual management prelude ownership, finite authentication and cancellation.

#[tokio::test]
#[ignore = "requires PostgreSQL; scoped API-key candidate maximum and excess refusal before mutation"]
async fn pg_organizations_management_api_key_candidate_bound() -> TestResult {
    let f = RenameHistoryFixture::new().await?;
    let services: Vec<Uuid> = (0..33).map(|_| Uuid::new_v4()).collect();
    let result = history_test(async {
        for service in &services {
            sqlx::query("INSERT INTO aegaeon.administrators(id,email,password_hash,kind) VALUES($1,$2,'disabled-service-login','SERVICE')")
                .bind(service).bind(format!("service-{service}@example.com")).execute(&f.user.runtime).await?;
        }
        let prefix = format!("aeg_{}", &Uuid::new_v4().simple().to_string()[..8]);
        let secret = format!("{prefix}_{}", Uuid::new_v4().simple());
        let mut selected = Uuid::nil();
        for (index, service) in services.iter().take(32).enumerate() {
            let hash = if index == 0 { super::sha256_array(secret.as_bytes()) }
                else { super::sha256_array(Uuid::new_v4().as_bytes()) };
            let id: Uuid = sqlx::query_scalar("INSERT INTO aegaeon.api_keys(team_id,service_administrator_id,name,key_prefix,key_hash) VALUES($1,$2,$3,$4,$5) RETURNING id")
                .bind(f.user.env.team_id).bind(service).bind(format!("candidate {index}"))
                .bind(&prefix).bind(hash.as_slice()).fetch_one(&f.user.runtime).await?;
            sqlx::query("INSERT INTO aegaeon.api_key_capabilities(api_key_id,capability) VALUES($1,'READ')")
                .bind(id).execute(&f.user.runtime).await?;
            if index == 0 { selected = id; }
        }
        let state = test_app_state(f.user.runtime.clone(), test_management_state())?;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {secret}").parse()?);
        let authenticated = f.witness.run(super::require_management_session_async(&state, &headers, "bounded-key")).await?;
        assert!(authenticated.is_ok(), "exact maximum must authenticate");
        let touched: bool = sqlx::query_scalar("SELECT last_used_at IS NOT NULL FROM aegaeon.api_keys WHERE id=$1")
            .bind(selected).fetch_one(&f.user.runtime).await?;
        assert!(touched);
        sqlx::query("UPDATE aegaeon.api_keys SET last_used_at=NULL WHERE id=$1")
            .bind(selected).execute(&f.user.runtime).await?;
        sqlx::query("INSERT INTO aegaeon.api_keys(team_id,service_administrator_id,name,key_prefix,key_hash) VALUES($1,$2,'excess',$3,$4)")
            .bind(f.user.env.team_id).bind(services[32]).bind(&prefix)
            .bind(super::sha256_array(Uuid::new_v4().as_bytes()).as_slice()).execute(&f.user.runtime).await?;
        let refused = f.witness.run(super::require_management_session_async(&state, &headers, "excess-key")).await?;
        assert_eq!(refused.err().ok_or("excess prefix accepted")?.status(), StatusCode::SERVICE_UNAVAILABLE);
        let touched: bool = sqlx::query_scalar("SELECT last_used_at IS NOT NULL FROM aegaeon.api_keys WHERE id=$1")
            .bind(selected).fetch_one(&f.user.runtime).await?;
        assert!(!touched, "excess refusal must precede last-used mutation");
        // The ordinary unscoped contract is retained. It cannot be selected by
        // an invalid explicit Organizations owner.
        assert!(super::require_management_session_async(&state, &headers, "ordinary-key").await.is_ok());
        let bare = crate::organizations::request_work::Admission::isolated_for_test()?;
        let refused = bare.store_scope(super::require_management_session_async(&state, &headers, "bare-key")).await?;
        assert_eq!(refused.err().ok_or("bare scope accepted")?.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    }).await;
    let cleanup = async {
        sqlx::query("DELETE FROM aegaeon.api_keys WHERE service_administrator_id=ANY($1)")
            .bind(&services)
            .execute(&f.user.runtime)
            .await?;
        sqlx::query("DELETE FROM aegaeon.administrators WHERE id=ANY($1)")
            .bind(&services)
            .execute(&f.user.runtime)
            .await?;
        Ok::<(), sqlx::Error>(())
    }
    .await;
    f.finish(result.and(cleanup.map_err(Into::into))).await
}

async fn management_prelude_cancel(table: &'static str) -> TestResult {
    let f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let mut barrier = f.user.admin.begin().await?;
        sqlx::query(&format!("LOCK TABLE aegaeon.{table} IN ACCESS EXCLUSIVE MODE"))
            .execute(&mut *barrier).await?;
        let request = membership_http_request(Method::PATCH, &f.user.env,
            &format!("users/{}", f.owner), &f.user.sid,
            serde_json::json!({"email":"owned-update@example.com"}))?;
        let app = f.user.app.clone();
        let work = f.witness.begin().await?;
        let label = work.admission().store_label()?.ok_or("missing work label")?.to_owned();
        let response_waiter = tokio::spawn(work.execute(async move { app.oneshot(request).await }));
        let observed = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')")
                    .bind(&label).fetch_one(&f.user.admin).await?;
                if waiting { return Ok::<(), sqlx::Error>(()); }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }).await;
        response_waiter.abort();
        let cancelled = response_waiter.await;
        let pending = f.witness.pending().await;
        // Always release the primary barrier, including a failed ownership
        // observation, so the retained actual request can finish and clean up.
        let release = barrier.rollback().await;
        let completed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if f.witness.pending().await? == 0 { return Ok::<(), anyhow::Error>(()); }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await;
        observed??;
        assert!(cancelled.is_err_and(|error| error.is_cancelled()));
        assert_eq!(pending?, 1, "response cancellation must retain actual work");
        release?;
        completed??;
        let email: String = sqlx::query_scalar("SELECT email FROM aegaeon.end_users WHERE id=$1")
            .bind(f.owner).fetch_one(&f.user.runtime).await?;
        assert_eq!(email, "owned-update@example.com");
        Ok(())
    }).await;
    f.finish(result).await
}

macro_rules! prelude_owner_test {
    ($name:ident, $table:literal) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL; actual blocked prelude query retains work identity through response cancellation"]
        async fn $name() -> TestResult { management_prelude_cancel($table).await }
    };
}
prelude_owner_test!(
    pg_organizations_management_human_lookup_owned,
    "administrators"
);
prelude_owner_test!(
    pg_organizations_management_role_lookup_owned,
    "team_memberships"
);
prelude_owner_test!(
    pg_organizations_management_environment_lookup_owned,
    "environments"
);
prelude_owner_test!(pg_organizations_management_etag_lookup_owned, "end_users");
