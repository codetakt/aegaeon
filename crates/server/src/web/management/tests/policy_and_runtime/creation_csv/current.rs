#[tokio::test]
#[ignore = "requires PostgreSQL; committed authority revocation after allocation blocks CSV identity and activation issuance"]
async fn pg_organizations_creation_csv_current_authority() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let key = Uuid::new_v4().to_string();
    let body = csv_body(true);
    let result=history_test(async {
        let mut barrier=f.witness.history_append_barrier().await?;
        let keys=[key.as_str()];let call=retained_csv_request(&f,&keys,body.clone());tokio::pin!(call);
        let control=async {
            let observed=f.witness.wait_for_creation_prepare().await;
            let revoked=sqlx::query("UPDATE aegaeon.team_memberships SET role='AUDITOR' WHERE team_id=$1 AND administrator_id=$2").bind(f.user.env.team_id).bind(f.user.env.administrator_id).execute(&f.user.admin).await;
            let release=sqlx::query("ROLLBACK").execute(&mut barrier).await;
            let close=sqlx::Connection::close(barrier).await;
            observed?;revoked?;release?;close?;Ok::<(),Box<dyn StdError>>(())
        };
        let(response,control)=tokio::join!(&mut call,control);control?;assert_eq!(response?.status(),StatusCode::FORBIDDEN);
        assert_eq!(retained_csv_counts(&f).await?,(0,0,0));
        Ok(())
    }).await;
    let restored = sqlx::query(
        "UPDATE aegaeon.team_memberships SET role='OWNER' WHERE team_id=$1 AND administrator_id=$2",
    )
    .bind(f.user.env.team_id)
    .bind(f.user.env.administrator_id)
    .execute(&f.user.admin)
    .await;
    let result = history_test(async {
        result?;
        restored?;
        let (id, state, attempt) = f.witness.retained_creation("csv-a").await?;
        assert_eq!((state, attempt), ("retryable".into(), 1));
        let response = retained_csv_request(&f, &[&key], body).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json(response).await?["importedUsers"][0]["user"]["id"],
            id.to_string()
        );
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; current TTL policy is enforced after allocation without rebinding the original request"]
async fn pg_organizations_creation_csv_current_policy() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let key = Uuid::new_v4().to_string();
    let body = csv_body(true);
    let original: (i32,i32,i32) = sqlx::query_as("SELECT activation_token_default_ttl_seconds,password_reset_token_default_ttl_seconds,recovery_token_max_ttl_seconds FROM aegaeon.environment_policies WHERE environment_id=$1")
        .bind(f.user.env.environment_id).fetch_one(&f.user.admin).await?;
    let result = history_test(async {
        let mut barrier = f.witness.history_append_barrier().await?;
        let keys = [key.as_str()];
        let call = retained_csv_request(&f, &keys, body.clone());
        tokio::pin!(call);
        let control = async {
            let observed = f.witness.wait_for_creation_prepare().await;
            let altered = sqlx::query("UPDATE aegaeon.environment_policies SET activation_token_default_ttl_seconds=300,password_reset_token_default_ttl_seconds=300,recovery_token_max_ttl_seconds=300 WHERE environment_id=$1")
                .bind(f.user.env.environment_id).execute(&f.user.admin).await;
            let release = sqlx::query("ROLLBACK").execute(&mut barrier).await;
            let close = sqlx::Connection::close(barrier).await;
            observed?;
            altered?;
            release?;
            close?;
            Ok::<(), Box<dyn StdError>>(())
        };
        let (response, control) = tokio::join!(&mut call, control);
        control?;
        assert_eq!(response?.status(), StatusCode::BAD_REQUEST);
        assert_eq!(retained_csv_counts(&f).await?, (0, 0, 0));
        Ok(())
    })
    .await;
    let restored = sqlx::query("UPDATE aegaeon.environment_policies SET activation_token_default_ttl_seconds=$2,password_reset_token_default_ttl_seconds=$3,recovery_token_max_ttl_seconds=$4 WHERE environment_id=$1")
        .bind(f.user.env.environment_id).bind(original.0).bind(original.1).bind(original.2).execute(&f.user.admin).await;
    let result = history_test(async {
        result?;
        restored?;
        let (id, state, attempt) = f.witness.retained_creation("csv-a").await?;
        assert_eq!((state, attempt), ("retryable".into(), 1));
        let response = retained_csv_request(&f, &[&key], body).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json(response).await?["importedUsers"][0]["user"]["id"],
            id.to_string()
        );
        assert_eq!(
            f.witness.retained_creation("csv-a").await?,
            (id, "committed".into(), 2)
        );
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; current CSV policy and issuer remain locked until primary commit"]
async fn pg_organizations_creation_csv_current_locks() -> TestResult {
    let f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let mut barrier = f.user.admin.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.organization_creation_receipts IN SHARE MODE")
            .execute(&mut *barrier).await?;
        let work = f.witness.begin().await?;
        let label = work.admission().store_label()?.ok_or("work label")?.to_owned();
        let owner = work.admission().clone();
        let app = f.user.app.clone();
        let mut request = membership_http_request(Method::POST, &f.user.env, "users/importCsv", &f.user.sid, csv_body(true))?;
        request.headers_mut().insert("idempotency-key", Uuid::new_v4().to_string().parse()?);
        let execution = tokio::spawn(async move { owner.store_scope(app.oneshot(request)).await });
        let observed = creation_primary_wait(&f.user.admin, &label).await;
        let conflicts = async {
            observed?;
            let mut blocked = Vec::new();
            for statement in [
                "UPDATE aegaeon.environment_policies SET recovery_token_max_ttl_seconds=recovery_token_max_ttl_seconds WHERE environment_id=$1",
                "UPDATE aegaeon.environments SET name=name WHERE id=$1",
                "UPDATE aegaeon.tenants SET name=name WHERE id=(SELECT tenant_id FROM aegaeon.environments WHERE id=$1)",
            ] {
                let mut change = f.user.admin.begin().await?;
                sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *change).await?;
                let result = sqlx::query(statement).bind(f.user.env.environment_id).execute(&mut *change).await;
                let rejected = result.as_ref().err().and_then(sqlx::Error::as_database_error)
                    .and_then(|error| error.code()).is_some_and(|code| code == "55P03");
                change.rollback().await?;
                blocked.push(rejected);
            }
            Ok::<_,Box<dyn StdError>>(blocked)
        }.await;
        let released = barrier.rollback().await;
        let response = execution.await;
        released?;
        assert_eq!(response???.status(), StatusCode::OK);
        assert_eq!(work.complete().await?.pending, 0);
        assert_eq!(conflicts?, vec![true, true, true]);
        assert_eq!(retained_csv_counts(&f).await?, (2, 2, 2));
        Ok(())
    }).await;
    f.finish(result).await
}
