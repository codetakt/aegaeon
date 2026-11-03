use super::*;
use serde_json::json;

async fn local_url(fixture: &Fixture, revision: i64, value: &str) -> Result {
    let mut tx = fixture
        .state
        .management
        .database
        .as_ref()
        .ok_or("writer pool")?
        .begin()
        .await?;
    crate::attribute_mapping::replace_local_attributes(
        &mut tx,
        fixture.state.environment_id,
        fixture.user,
        revision,
        &json!({"nickname": value}),
        fixture.author,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_lti_mapped_resource_urls_recheck_current_values_before_signing() -> Result {
    for name in ["profile", "picture", "website"] {
        let mut fixture = Fixture::new(false, false).await?;
        let mapping = fixture.config.mapping.outputs["nickname"].clone();
        fixture.config.mapping.outputs.insert(name.into(), mapping);
        fixture.config.mapping.released_outputs.insert(name.into());
        fixture.replace(1).await?;
        let secure = "https://platform.example/user/1?size=large#portrait";
        local_url(&fixture, 1, secure).await?;
        let path = fixture.create().await?;
        let request = fixture.initiate(&path, false).await?;
        let url = format!("/lti/authorize?{request}");
        // Stored values can change after a valid launch was initiated.
        local_url(&fixture, 2, "http://platform.example/user/1").await?;
        let refused = body(fixture.send("GET", &url, true, None, None).await?).await?;
        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{name}");
        assert!(!refused.1.contains("name=\"id_token\""));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='lti.launch.issued.v1'")
            .bind(fixture.state.environment_id).fetch_one(&fixture.state.db_pool).await?;
        assert_eq!(count, 0, "a rejected resource must not be issued");
        // Repairing the source permits one issuance; a refusal did not consume it.
        local_url(&fixture, 3, secure).await?;
        let success = body(fixture.send("GET", &url, true, None, None).await?).await?;
        assert_eq!(success.0, StatusCode::OK);
        let claims = fixture.verify(&hidden(&success.1, "id_token")?).await?;
        assert_eq!(claims[name], secure);
        let replay = body(fixture.send("GET", &url, true, None, None).await?).await?;
        assert!(!replay.1.contains("name=\"id_token\""));
    }
    Ok(())
}
