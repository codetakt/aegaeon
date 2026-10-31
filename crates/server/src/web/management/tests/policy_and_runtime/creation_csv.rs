fn csv_http_request(
    f: &RenameHistoryFixture,
    keys: &[&str],
) -> Result<axum::http::Request<Body>, Box<dyn StdError>> {
    let mut request = membership_http_request(
        Method::POST,
        &f.user.env,
        "users/importCsv",
        &f.user.sid,
        csv_body(true),
    )?;
    for key in keys {
        request
            .headers_mut()
            .append("idempotency-key", key.parse()?);
    }
    Ok(request)
}
async fn retained_csv_request(
    f: &RenameHistoryFixture,
    keys: &[&str],
    body: serde_json::Value,
) -> Result<axum::response::Response, Box<dyn StdError>> {
    let mut request = membership_http_request(
        Method::POST,
        &f.user.env,
        "users/importCsv",
        &f.user.sid,
        body,
    )?;
    for key in keys {
        request
            .headers_mut()
            .append("idempotency-key", key.parse()?);
    }
    Ok(f.witness.run(f.user.app.clone().oneshot(request)).await??)
}
fn csv_body(activation: bool) -> serde_json::Value {
    serde_json::json!({"csv":"subject,email\ncsv-a,a@example.test\ncsv-b,b@example.test\n","issueActivationTokens":activation,"activationTokenExpiresInSeconds":600})
}
async fn retained_csv_counts(
    f: &RenameHistoryFixture,
) -> Result<(i64, i64, i64), Box<dyn StdError>> {
    Ok(sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1 AND subject IN ('csv-a','csv-b')),(SELECT count(*) FROM aegaeon.end_user_recovery_tokens r JOIN aegaeon.end_users u ON u.id=r.end_user_id WHERE u.environment_id=$1),(SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.user.imported.v1')")
        .bind(f.user.env.environment_id).fetch_one(&f.user.runtime).await?)
}
#[tokio::test]
#[ignore = "requires PostgreSQL; finite CSV input rejects before allocation; maximum batch has retained replay"]
async fn pg_organizations_creation_csv_bounds_and_replay() -> TestResult {
    let f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let key = Uuid::new_v4().to_string();
        for keys in [vec![], vec!["invalid"], vec![key.as_str(), key.as_str()]] {
            assert_eq!(
                retained_csv_request(&f, &keys, csv_body(false))
                    .await?
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        for ttl in [0, 299, 604_801] {
            let mut invalid = csv_body(true);
            invalid["activationTokenExpiresInSeconds"] = ttl.into();
            assert_eq!(
                retained_csv_request(&f, &[&key], invalid).await?.status(),
                StatusCode::BAD_REQUEST
            );
        }
        let csv = format!(
            "subject\n{}",
            (0..101).map(|i| format!("csv-{i}\n")).collect::<String>()
        );
        assert_eq!(
            retained_csv_request(&f, &[&key], serde_json::json!({"csv":csv}))
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        let csv = format!(
            "subject\n{}",
            (0..100).map(|i| format!("csv-{i}\n")).collect::<String>()
        );
        let body = serde_json::json!({"csv":csv});
        let initial = retained_csv_request(&f, &[&key], body.clone()).await?;
        assert_eq!(initial.status(), StatusCode::OK);
        let first = response_json(initial).await?;
        assert_eq!(first["importedUsers"].as_array().ok_or("rows")?.len(), 100);
        let receipts:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_creation_receipts WHERE environment_id=$1 AND kind='management_csv'")
            .bind(f.user.env.environment_id).fetch_one(&f.user.runtime).await?;
        assert_eq!(receipts,100);

        let replay = retained_csv_request(&f, &[&key], body.clone()).await?;
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(response_json(replay).await?, first);
        let id = first["importedUsers"][0]["user"]["id"]
            .as_str()
            .ok_or("id")?;
        let renamed = f
            .user
            .send(
                Method::PATCH,
                &format!("users/{id}"),
                serde_json::json!({"subject":"csv-renamed"}),
            )
            .await?;
        assert!(renamed.status().is_success());
        let replay = response_json(retained_csv_request(&f, &[&key], body.clone()).await?).await?;
        assert_eq!(replay["importedUsers"][0]["user"]["subject"], "csv-renamed");
        assert!(f
            .user
            .send(
                Method::DELETE,
                &format!("users/{id}"),
                serde_json::json!({})
            )
            .await?
            .status()
            .is_success());
        assert_eq!(
            retained_csv_request(&f, &[&key], body).await?.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    f.finish(result).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; whole batch, order, TTL and activation binding refuse rebinding and repeated secrets"]
async fn pg_organizations_creation_csv_binding_tokens() -> TestResult {
    let f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let key = Uuid::new_v4().to_string();
        let body = csv_body(true);
        let response = retained_csv_request(&f, &[&key], body.clone()).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let value = response_json(response).await?;
        assert!(value["importedUsers"][0]["activation"]["token"].is_string());
        assert_eq!(retained_csv_counts(&f).await?, (2, 2, 2));
        let response = retained_csv_request(&f, &[&key], body.clone()).await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(response).await?["errorCode"],
            "one_time_result_unavailable"
        );
        for (field, value) in [
            ("issueActivationTokens", serde_json::json!(false)),
            ("activationTokenExpiresInSeconds", serde_json::json!(601)),
            (
                "csv",
                serde_json::json!("subject,email\ncsv-b,b@example.test\ncsv-a,a@example.test\n"),
            ),
            (
                "csv",
                serde_json::json!("subject,email\ncsv-a,a@example.test\ncsv-c,c@example.test\n"),
            ),
            (
                "csv",
                serde_json::json!(
                    "subject,email\ncsv-a,changed@example.test\ncsv-b,b@example.test\n"
                ),
            ),
        ] {
            let mut changed = body.clone();
            changed[field] = value;
            assert_eq!(
                retained_csv_request(&f, &[&key], changed).await?.status(),
                StatusCode::CONFLICT
            );
        }
        assert_eq!(retained_csv_counts(&f).await?, (2, 2, 2));
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    f.finish(result).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; a second-row primary failure rolls back all identities/secrets/audits and retries same owners"]
async fn pg_organizations_creation_csv_rollback() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let key = Uuid::new_v4().to_string();
    let name = format!("csv_failure_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id='{}'::uuid AND NEW.event_type='management.user.imported.v1' AND NEW.data->>'subject'='csv-b' THEN RAISE EXCEPTION 'injected second-row audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.{name}()",f.user.env.environment_id)).execute(&f.user.admin).await?;
    let result = history_test(async {
        assert!(!retained_csv_request(&f, &[&key], csv_body(true))
            .await?
            .status()
            .is_success());
        for subject in ["csv-a", "csv-b"] {
            let (_, state, attempt) = f.witness.retained_creation(subject).await?;
            assert_eq!((state, attempt), ("retryable".into(), 1));
        }
        assert_eq!(retained_csv_counts(&f).await?, (0, 0, 0));
        Ok(())
    })
    .await;
    let cleanup = sqlx::raw_sql(&format!(
        "DROP TRIGGER {name} ON aegaeon.audit_events; DROP FUNCTION aegaeon.{name}()"
    ))
    .execute(&f.user.admin)
    .await;
    let result = history_test(async {
        result?;
        cleanup?;
        let owners = [
            f.witness.retained_creation("csv-a").await?.0,
            f.witness.retained_creation("csv-b").await?.0,
        ];
        let response = retained_csv_request(&f, &[&key], csv_body(true)).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let value = response_json(response).await?;
        for (i, subject) in ["csv-a", "csv-b"].iter().enumerate() {
            assert_eq!(
                value["importedUsers"][i]["user"]["id"],
                owners[i].to_string()
            );
            assert_eq!(
                f.witness.retained_creation(subject).await?,
                (owners[i], "committed".into(), 2)
            );
        }
        assert_eq!(retained_csv_counts(&f).await?, (2, 2, 2));
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    f.finish(result).await
}
include!("creation_csv/current.rs");

include!("creation_csv/failures.rs");

include!("creation_csv/receipt.rs");
