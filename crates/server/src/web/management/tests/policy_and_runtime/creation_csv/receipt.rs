#[tokio::test]
#[ignore = "requires PostgreSQL; runtime cannot mutate immutable receipts and damaged second-row primary evidence refuses whole-batch replay"]
async fn pg_organizations_creation_csv_receipt_integrity() -> TestResult {
    let f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let key = Uuid::new_v4().to_string();
        let response = retained_csv_request(&f, &[&key], csv_body(true)).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let id:Uuid = response_json(response).await?["importedUsers"][1]["user"]["id"].as_str().ok_or("id")?.parse()?;
        let original:serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(r) FROM aegaeon.organization_creation_receipts r WHERE owner_id=$1")
            .bind(id).fetch_one(&f.user.runtime).await?;
        for statement in [
            "INSERT INTO aegaeon.organization_creation_receipts SELECT * FROM aegaeon.organization_creation_receipts",
            "UPDATE aegaeon.organization_creation_receipts SET subject=subject",
            "DELETE FROM aegaeon.organization_creation_receipts",
            "TRUNCATE aegaeon.organization_creation_receipts",
            "ALTER TABLE aegaeon.organization_creation_receipts DISABLE TRIGGER ALL",
        ] {
            let mut tx = f.user.runtime.begin().await?;
            let denied = sqlx::query(statement).execute(&mut *tx).await.is_err();
            tx.rollback().await?;
            assert!(denied, "runtime receipt mutation was allowed: {statement}");
        }
        for statement in [
            "DELETE FROM aegaeon.organization_creation_receipts WHERE owner_id=$1",
            "UPDATE aegaeon.organization_creation_receipts SET receipt_sha256=decode(repeat('00',32),'hex') WHERE owner_id=$1",
        ] {
            // An explicit privileged fixture models missing/corrupt restored
            // primary data. It is not a runtime operation or a recovery claim.
            let mut fault = f.user.admin.begin().await?;
            sqlx::query("SET LOCAL session_replication_role=replica").execute(&mut *fault).await?;
            sqlx::query(statement).bind(id).execute(&mut *fault).await?;
            fault.commit().await?;
            let work = f.witness.begin().await?;
            let closure = work.admission().closure_probe_for_test();
            let before = f.user.snapshot().await?;
            let replay = work.store_scope(f.user.app.clone().oneshot(csv_http_request(&f, &[&key])?)).await;
            let completed = work.complete().await;
            let after = f.user.snapshot().await?;
            // Restore fixture bytes before evaluating assertions, including a
            // mutant that wrongly accepted the replay. No pending work is reset.
            let mut restore = f.user.admin.begin().await?;
            sqlx::query("SET LOCAL session_replication_role=replica").execute(&mut *restore).await?;
            sqlx::query("DELETE FROM aegaeon.organization_creation_receipts WHERE owner_id=$1").bind(id).execute(&mut *restore).await?;
            sqlx::query("INSERT INTO aegaeon.organization_creation_receipts SELECT * FROM jsonb_populate_record(NULL::aegaeon.organization_creation_receipts,$1)")
                .bind(&original).execute(&mut *restore).await?;
            restore.commit().await?;
            assert!(replay.is_err() && completed.is_err() && closure.is_closed());
            assert_eq!(before, after);
        }
        assert_eq!(f.witness.pending().await?, 2);
        Ok(())
    }).await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; same key and subject in separate Environments retain distinct owners"]
async fn pg_organizations_creation_csv_environment_binding() -> TestResult {
    let a = RenameHistoryFixture::new().await?;
    let b = SubjectOwnershipFixture::new().await?;
    let result = history_test(async {
        let key = Uuid::new_v4().to_string();
        let first = retained_csv_request(&a, &[&key], csv_body(true)).await?;
        let mut request = membership_http_request(
            Method::POST,
            &b.env,
            "users/importCsv",
            &b.sid,
            csv_body(true),
        )?;
        request
            .headers_mut()
            .insert("idempotency-key", key.parse()?);
        let second = a
            .witness
            .run_new_environment(b.env.environment_id, b.app.clone().oneshot(request))
            .await??;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_ne!(
            response_json(first).await?["importedUsers"][0]["user"]["id"],
            response_json(second).await?["importedUsers"][0]["user"]["id"]
        );
        let before = a.user.snapshot().await?;
        let before_b = b.snapshot().await?;
        let mut request = membership_http_request(
            Method::POST,
            &b.env,
            "users/importCsv",
            &b.sid,
            csv_body(true),
        )?;
        request
            .headers_mut()
            .insert("idempotency-key", key.parse()?);
        let foreign = a.witness.run(b.app.clone().oneshot(request)).await??;
        assert_eq!(foreign.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(before, a.user.snapshot().await?);
        assert_eq!(a.witness.pending().await?, 0);
        assert_eq!(before_b, b.snapshot().await?);
        Ok(())
    })
    .await;
    let cleaned = cleanup_creation_secondary(b).await;
    a.finish(result.and(cleaned)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; another authorized human cannot take over the retained operation"]
async fn pg_organizations_creation_csv_actor_binding() -> TestResult {
    let mut a = RenameHistoryFixture::new().await?;
    let b = SubjectOwnershipFixture::new().await?;
    let result = history_test(async {
        let key=Uuid::new_v4().to_string();
        assert_eq!(retained_csv_request(&a,&[&key],csv_body(true)).await?.status(),StatusCode::OK);
        sqlx::query("INSERT INTO aegaeon.team_memberships(team_id,administrator_id,role) VALUES($1,$2,'OWNER')")
            .bind(a.user.env.team_id).bind(b.env.administrator_id).execute(&a.user.admin).await?;
        let mgmt=test_management_state();
        a.user.sid=mgmt.sessions.create(b.env.administrator_id,crate::util::now_unix_epoch_secs()?).ok_or("second session")?;
        a.user.app=super::super::build_router(test_app_state(a.user.runtime.clone(),mgmt)?);
        let before=a.user.snapshot().await?;
        let response=retained_csv_request(&a,&[&key],csv_body(true)).await?;
        assert_eq!(response.status(),StatusCode::CONFLICT);
        assert_eq!(response_json(response).await?["message"],"Identity creation conflict");
        assert_eq!(before,a.user.snapshot().await?);
        assert_eq!(a.witness.pending().await?,0);
        Ok(())
    }).await;
    let removed = sqlx::query(
        "DELETE FROM aegaeon.team_memberships WHERE team_id=$1 AND administrator_id=$2",
    )
    .bind(a.user.env.team_id)
    .bind(b.env.administrator_id)
    .execute(&a.user.admin)
    .await;
    let cleaned = cleanup_creation_secondary(b).await;
    a.finish(
        result
            .and(removed.map(|_| ()).map_err(Into::into))
            .and(cleaned),
    )
    .await
}
