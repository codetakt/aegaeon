use super::*;
use crate::application_authorization::{store as projections, Authority};
use serde_json::{json, Value};
use std::time::Duration;

async fn projected_fixture() -> Result<Fixture> {
    let mut fixture = Fixture::new(false, false).await?;
    fixture.state.db_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect_with(fixture.state.db_pool.connect_options().as_ref().clone())
        .await?;
    let audience = format!(
        "{}/lti/launches",
        fixture.state.issuer.trim_end_matches('/')
    );
    sqlx::query("INSERT INTO aegaeon.application_authorizations(environment_id,client_id,subject,revision,authority,source_revision,audiences,claims,enabled,client_record_id) SELECT environment_id,client_identifier,client_identifier,1,'operator',1,$2,$3,true,id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier='context-producer' AND status='ACTIVE' AND deleted_at IS NULL")
        .bind(fixture.state.environment_id).bind(json!([audience]))
        .bind(json!({"roles":[],"organization_roles":[]})).execute(&fixture.state.db_pool).await?;
    fixture.state.application_authority = Some(std::sync::Arc::new(Authority {
        projections: fixture.state.db_pool.clone(),
        memberships: None,
    }));
    fixture.state.validate_subject_namespace().await?;
    fixture.access_token = fixture.issue("lti:launch", &audience).await?;
    let meta = fixture
        .state
        .tokens
        .store
        .try_get_bearer_meta(&fixture.access_token)?
        .ok_or("metadata")?;
    assert!(meta.application_grant.is_some());
    Ok(fixture)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_application_projection_rechecked_before_create_and_issue() -> Result {
    for update in ["enabled=false,revision=2", "revision=2"] {
        let fixture = projected_fixture().await?;
        let path = fixture.create().await?;
        let request = fixture.initiate(&path, false).await?;
        // Final consumption must consult the captured grant, not current additions.
        sqlx::query(&format!(
            "UPDATE aegaeon.application_authorizations SET {update} WHERE environment_id=$1"
        ))
        .bind(fixture.state.environment_id)
        .execute(&fixture.state.db_pool)
        .await?;
        let denied = fixture.create_response().await?;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert!(denied.headers()["www-authenticate"]
            .to_str()?
            .starts_with("Bearer "));
        let denied = body(
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
        assert_eq!(denied.0, StatusCode::FORBIDDEN, "{}", denied.1);
        assert!(!denied.1.contains("name=\"id_token\""));
        let issued: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='lti.launch.issued.v1'")
            .bind(fixture.state.environment_id).fetch_one(&fixture.state.db_pool).await?;
        assert_eq!(issued, 0);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_application_snapshot_retained_with_single_connection_and_fail_closed() -> Result {
    let mut fixture = projected_fixture().await?;
    let path = fixture.create().await?;
    let value: Value = sqlx::query_scalar(
        "SELECT producer_metadata FROM aegaeon.lti_launch_intents WHERE environment_id=$1",
    )
    .bind(fixture.state.environment_id)
    .fetch_one(&fixture.state.db_pool)
    .await?;
    assert_eq!(value["application_grant"]["revision"], 1);
    assert_eq!(value["token_id"], "");
    let authority = fixture.state.application_authority.take();
    assert_eq!(
        fixture.create_response().await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        fixture.send("GET", &path, true, None, None).await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture.state.application_authority = authority;
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
    fixture.verify(&hidden(&issued.1, "id_token")?).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_application_projection_lock_prevents_mid_publication_revocation() -> Result {
    let fixture = projected_fixture().await?;
    let meta = fixture
        .state
        .tokens
        .store
        .try_get_bearer_meta(&fixture.access_token)?
        .ok_or("metadata")?;
    let grant = meta.application_grant.as_ref().ok_or("grant")?;
    let mut transaction = fixture.state.db_pool.begin().await?;
    super::super::current_application_grant(&fixture.state, &mut transaction, &meta)
        .await
        .map_err(|_| "current grant")?;
    let writer_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(fixture.state.db_pool.connect_options().as_ref().clone())
        .await?;
    let error = sqlx::query("SELECT revision FROM aegaeon.application_authorizations WHERE environment_id=$1 FOR UPDATE NOWAIT")
        .bind(fixture.state.environment_id).fetch_one(&writer_pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("55P03")
    );
    transaction.commit().await?;
    sqlx::query("UPDATE aegaeon.application_authorizations SET enabled=false,revision=2 WHERE environment_id=$1")
        .bind(fixture.state.environment_id).execute(&writer_pool).await?;
    assert!(
        !projections::is_current(
            &writer_pool,
            fixture.state.environment_id,
            &fixture.state.issuer,
            grant
        )
        .await?
    );
    writer_pool.close().await;
    Ok(())
}
