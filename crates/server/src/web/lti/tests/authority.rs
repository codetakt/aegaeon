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

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_independent_launches_share_authority_but_exclude_writers() -> Result {
    use crate::lti::intents;
    use std::time::Duration;
    let mut fixture = Fixture::new(false, false).await?;
    let first = fixture.create().await?;
    let first_request = fixture.initiate(&first, false).await?;
    let second = fixture.create().await?;
    let second_request = fixture.initiate(&second, false).await?;
    let mut held = fixture.state.db_pool.begin().await?;
    super::super::current_runtime(&fixture.state, &mut held).await?;
    store::load(&mut held, fixture.state.environment_id, "tool", true).await?;
    let ticket = first.rsplit('/').next().ok_or("missing ticket")?;
    let intent = intents::load(
        &mut held,
        fixture.state.environment_id,
        ticket,
        intents::Ticket::Browser,
    )
    .await?;
    // An unrelated real authorize request must complete while the first launch
    // retains all its authority and consumption locks (e.g. a slow signer).
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        fixture.send(
            "GET",
            &format!("/lti/authorize?{second_request}"),
            true,
            None,
            None,
        ),
    )
    .await??;
    fixture
        .verify(&hidden(&body(response).await?.1, "id_token")?)
        .await?;
    for (query, id) in [
        (
            "SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE NOWAIT",
            fixture.state.environment_id,
        ),
        (
            "SELECT id FROM aegaeon.lti_registrations WHERE id=$1 FOR UPDATE NOWAIT",
            intent.registration_id,
        ),
        (
            "SELECT id FROM aegaeon.lti_launch_intents WHERE id=$1 FOR UPDATE NOWAIT",
            intent.id,
        ),
    ] {
        let mut writer = fixture.state.db_pool.begin().await?;
        let error = sqlx::query(query)
            .bind(id)
            .fetch_one(&mut *writer)
            .await
            .unwrap_err();
        assert_eq!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("55P03")
        );
        writer.rollback().await?;
    }
    held.rollback().await?;
    fixture.config.status = Lifecycle::Disabled;
    fixture.replace(1).await?;
    let refused = fixture
        .send(
            "GET",
            &format!("/lti/authorize?{first_request}"),
            true,
            None,
            None,
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_producer_revocation_during_create_does_not_consume_budget() -> Result {
    use std::time::Duration;
    let fixture = Fixture::new(false, false).await?;
    let mut writer = fixture.state.db_pool.begin().await?;
    let client: uuid::Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier='context-producer' AND status='ACTIVE' FOR UPDATE")
        .bind(fixture.state.environment_id).fetch_one(&mut *writer).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await?;
    let original: Vec<String> =
        sqlx::query_scalar("SELECT allowed_scopes FROM aegaeon.clients WHERE id=$1")
            .bind(client)
            .fetch_one(&mut *writer)
            .await?;
    let creation = fixture.create_response();
    tokio::pin!(creation);
    let blocked = async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename=current_user AND $1=ANY(pg_blocking_pids(pid)))")
                .bind(pid).fetch_one(&fixture.state.db_pool).await?;
            if waiting {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        response = &mut creation => {
            return Err(format!("intent returned before producer lock: {}", response?.status()).into());
        }
        result = tokio::time::timeout(Duration::from_secs(3), blocked) => { result??; }
    }
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=ARRAY[]::text[] WHERE id=$1")
        .bind(client)
        .execute(&mut *writer)
        .await?;
    writer.commit().await?;
    let denied = tokio::time::timeout(Duration::from_secs(3), creation).await??;
    assert!(matches!(
        denied.status(),
        StatusCode::FORBIDDEN | StatusCode::SERVICE_UNAVAILABLE
    ));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.lti_launch_intents WHERE environment_id=$1",
    )
    .bind(fixture.state.environment_id)
    .fetch_one(&fixture.state.db_pool)
    .await?;
    assert_eq!(count, 0);
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=$2 WHERE id=$1")
        .bind(client)
        .bind(original)
        .execute(&fixture.state.db_pool)
        .await?;
    fixture.create().await?;
    Ok(())
}
