use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_launch_completes_with_one_connection() -> Result {
    let mut fixture = Fixture::new(false, false).await?;
    fixture.state.db_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_with(fixture.state.db_pool.connect_options().as_ref().clone())
        .await?;
    fixture.state.validate_subject_namespace().await?;
    let path = fixture.create().await?;
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
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    fixture.verify(&hidden(&response.1, "id_token")?).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_launch_requires_own_scope_and_audience_with_relaxed_generic_policy() -> Result {
    let mut fixture = Fixture::with_validation(false, false, false).await?;
    assert!(!fixture.state.cfg.security_policy.require_scope_subset());
    assert!(!fixture.state.cfg.security_policy.require_audience_match());
    let audience = format!(
        "{}/lti/launches",
        fixture.state.issuer.trim_end_matches('/')
    );
    let other = format!(
        "{}/other-resource",
        fixture.state.issuer.trim_end_matches('/')
    );
    for (scope, target, expected) in [
        ("unrelated", audience.as_str(), StatusCode::FORBIDDEN),
        ("lti:launch", other.as_str(), StatusCode::UNAUTHORIZED),
    ] {
        fixture.access_token = fixture.issue(scope, target).await?;
        assert_eq!(fixture.create_response().await?.status(), expected);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.lti_launch_intents WHERE environment_id=$1",
    )
    .bind(fixture.state.environment_id)
    .fetch_one(&fixture.state.db_pool)
    .await?;
    assert_eq!(count, 0);
    fixture.access_token = fixture.issue("lti:launch", &audience).await?;
    fixture.create().await?;
    Ok(())
}
