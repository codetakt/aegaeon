use super::*;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and administrator supplier for isolated fault injection"]
async fn pg_lti_failed_audit_rolls_back_consumption_and_lost_delivery_cannot_reissue() -> Result {
    let fixture = Fixture::new(false, false).await?;
    let path = fixture.create().await?;
    let request = fixture.initiate(&path, false).await?;
    let options: sqlx::postgres::PgConnectOptions =
        std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?.parse()?;
    let database = fixture
        .state
        .db_pool
        .connect_options()
        .get_database()
        .ok_or("fixture database")?
        .to_owned();
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.database(&database))
        .await?;
    let name = format!("lti_audit_failure_{}", uuid::Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id='{}'::uuid AND NEW.event_type='lti.launch.issued.v1' THEN RAISE EXCEPTION 'injected LTI audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.{name}();",fixture.state.environment_id)).execute(&admin).await?;
    let result: Result = async {
        let failed = body(
            fixture
                .send(
                    "GET",
                    &format!("/lti/authorize?{request}"),
                    true,
                    None,
                    None,
                )
                .await?,
        )
        .await?;
        assert_eq!(failed.0, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!failed.1.contains("name=\"id_token\""));
        let status: String = sqlx::query_scalar(
            "SELECT status FROM aegaeon.lti_launch_intents WHERE environment_id=$1",
        )
        .bind(fixture.state.environment_id)
        .fetch_one(&fixture.state.db_pool)
        .await?;
        assert_eq!(status, "initiated");
        Ok(())
    }
    .await;
    sqlx::raw_sql(&format!(
        "DROP TRIGGER {name} ON aegaeon.audit_events; DROP FUNCTION aegaeon.{name}();"
    ))
    .execute(&admin)
    .await?;
    admin.close().await;
    result?;
    let response = fixture
        .send(
            "GET",
            &format!("/lti/authorize?{request}"),
            true,
            None,
            None,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response); // Simulate successful commit followed by undelivered HTTP response.
    let retry = body(
        fixture
            .send(
                "GET",
                &format!("/lti/authorize?{request}"),
                true,
                None,
                None,
            )
            .await?,
    )
    .await?;
    assert!(!retry.1.contains("name=\"id_token\""));
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_admission_budget_retains_completed_launches_and_expires_state() -> Result {
    let fixture = Fixture::new(false, false).await?;
    let path = fixture.create().await?;
    let request = fixture.initiate(&path, false).await?;
    let issued = body(
        fixture
            .send(
                "GET",
                &format!("/lti/authorize?{request}"),
                true,
                None,
                None,
            )
            .await?,
    )
    .await?;
    assert!(issued.1.contains("name=\"id_token\""));
    for _ in 1..32 {
        fixture.create().await?;
    }
    assert_eq!(
        fixture.create_response().await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // Early token expiry must not refund admission capacity before five minutes.
    sqlx::query("UPDATE aegaeon.lti_launch_intents SET created_at=created_at-2,expires_at=created_at-1 WHERE environment_id=$1")
        .bind(fixture.state.environment_id).execute(&fixture.state.db_pool).await?;
    assert_eq!(
        crate::lti::store::cleanup_expired(&fixture.state.db_pool, fixture.state.environment_id)
            .await?,
        0
    );
    assert_eq!(
        fixture.create_response().await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    sqlx::query("UPDATE aegaeon.lti_launch_intents SET created_at=created_at-600,expires_at=expires_at-600 WHERE environment_id=$1").bind(fixture.state.environment_id).execute(&fixture.state.db_pool).await?;
    assert_eq!(
        crate::lti::store::cleanup_expired(&fixture.state.db_pool, fixture.state.environment_id)
            .await?,
        32
    );
    let revisions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.lti_registrations WHERE environment_id=$1",
    )
    .bind(fixture.state.environment_id)
    .fetch_one(&fixture.state.db_pool)
    .await?;
    assert_eq!(revisions, 1);
    fixture.create().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_namespace_gate_precedes_all_public_launch_effects() -> Result {
    let mut fixture = Fixture::new(false, false).await?;
    let path = fixture.create().await?;
    let original = fixture.state.clone();
    fixture.state.subject_namespace = None;
    assert_eq!(
        fixture.create_response().await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    for (method, path) in [
        ("GET", path.as_str()),
        ("POST", path.as_str()),
        ("GET", "/lti/authorize"),
        ("POST", "/lti/authorize"),
        ("GET", "/lti/continue/invalid"),
    ] {
        assert_eq!(
            fixture
                .send(
                    method,
                    path,
                    true,
                    Some("application/x-www-form-urlencoded"),
                    Some(String::new())
                )
                .await?
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    fixture.state = original;
    let request = fixture.initiate(&path, false).await?;
    let response = body(
        fixture
            .send(
                "GET",
                &format!("/lti/authorize?{request}"),
                true,
                None,
                None,
            )
            .await?,
    )
    .await?;
    fixture.verify(&hidden(&response.1, "id_token")?).await?;
    Ok(())
}
