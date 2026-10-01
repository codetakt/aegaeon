#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_binding_reserved_subject_guard_covers_management_create_import_and_update() -> TestResult
{
    let f = BindingFixture::new().await?;
    let subject = "upstream:v2:managed-allocation";
    let (status, user) = f
        .post("users", serde_json::json!({"subject":subject}))
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{user}");
    let id = user["id"].as_str().ok_or("user id")?;
    let response = f
        .app
        .clone()
        .oneshot(membership_http_request(
            Method::PATCH,
            &f.env,
            &format!("users/{id}"),
            &f.sid,
            serde_json::json!({"subject":subject,"email":"unchanged@example.com"}),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response = f
        .app
        .clone()
        .oneshot(membership_http_request(
            Method::PATCH,
            &f.env,
            &format!("users/{id}"),
            &f.sid,
            serde_json::json!({"subject":"renamed-management-user"}),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response = f
        .app
        .clone()
        .oneshot(membership_http_request(
            Method::PATCH,
            &f.env,
            &format!("users/{id}"),
            &f.sid,
            serde_json::json!({"subject":subject}),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    for path in ["users", "users/invitations"] {
        let (status, value) = f.post(path, serde_json::json!({"subject":subject})).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{value}");
    }
    let (status, value) = f
        .post(
            "users/importCsv",
            serde_json::json!({"csv":format!("subject,email\n{subject},test@example.com\n")}),
        )
        .await?;
    assert_eq!(status, StatusCode::CONFLICT, "{value}");
    let fresh = "upstream:v2:import-allocation";
    let (status, value) = f
        .post(
            "users/importCsv",
            serde_json::json!({"csv":format!("subject,email\n{fresh},test@example.com\n")}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{value}");
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.upstream_subject_reservations WHERE environment_id=$1",
    )
    .bind(f.env.environment_id)
    .fetch_one(&f.pool)
    .await?;
    assert_eq!(count, 2);
    f.cleanup().await?;
    Ok(())
}
