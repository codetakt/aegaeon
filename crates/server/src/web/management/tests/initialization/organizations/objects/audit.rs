use super::*;
use axum::body::to_bytes;

async fn page(
    h: &Harness,
    path: &str,
    expected: StatusCode,
) -> Result<Value, Box<dyn std::error::Error>> {
    let response = h.app.clone().oneshot(h.read(path)).await?;
    assert_eq!(response.status(), expected);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = to_bytes(response.into_body(), 65536).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_audit_history_http_export_scope_pages_and_revocation(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let h = Harness::new(&pool).await?;
        let path = format!("{}/audit-events", h.collection.trim_end_matches("/organizations"));
        assert_eq!(h.app.clone().oneshot(Request::builder().uri(&path).body(Body::empty())?).await?.status(), StatusCode::UNAUTHORIZED);
        page(&h, &path, StatusCode::FORBIDDEN).await?;
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"export\"]',revision=revision+1 WHERE domain_id=$1 AND administrator_id=$2")
            .bind(h.domain).bind(h.administrator).execute(&pool).await?;
        let expected: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE environment_id=$1 AND domain_id=$2")
            .bind(h.environment).bind(h.domain).fetch_one(&pool).await?;
        assert!(expected > 1);
        let mut next = format!("{path}?pageSize=1");
        let mut ids = std::collections::BTreeSet::new();
        let mut cursor = None;
        for _ in 0..100 {
            let value = page(&h, &next, StatusCode::OK).await?;
            let events = value["events"].as_array().ok_or("events")?;
            assert_eq!(events.len(), 1);
            let event = &events[0];
            assert_eq!(event["environmentId"], h.environment.to_string());
            assert_eq!(event["domainId"], h.domain.to_string());
            let id = Uuid::parse_str(event["id"].as_str().ok_or("id")?)?;
            assert!(ids.insert(id), "no duplicate events in a stable traversal");
            let Some(token) = value["pageInfo"]["nextPageToken"].as_str() else { break; };
            cursor = Some(token.to_owned());
            next = format!("{path}?pageSize=1&pageToken={token}");
        }
        assert_eq!(ids.len() as i64, expected);
        let cursor = cursor.ok_or("nonempty cursor")?;
        let wrong_kind = cursor.replacen("audit-events.", "organizations.", 1);
        for query in ["pageSize=0".to_owned(), "pageSize=101".into(), "unknown=true".into(), "pageSize=1&pageSize=2".into(), format!("pageToken={wrong_kind}")] {
            page(&h, &format!("{path}?{query}"), StatusCode::BAD_REQUEST).await?;
        }
        let foreign = path.replace(&h.domain.to_string(), &Uuid::new_v4().to_string());
        page(&h, &foreign, StatusCode::FORBIDDEN).await?;
        page(&h, &format!("{foreign}?pageToken={cursor}"), StatusCode::BAD_REQUEST).await?;
        let head = h.app.clone().oneshot(Request::builder().method(Method::HEAD).uri(&path).header("cookie", &h.cookie).body(Body::empty())?).await?;
        assert_eq!(head.status(), StatusCode::OK);
        assert!(to_bytes(head.into_body(), 65536).await?.is_empty());
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false,revision=revision+1 WHERE domain_id=$1 AND administrator_id=$2")
            .bind(h.domain).bind(h.administrator).execute(&pool).await?;
        page(&h, &format!("{path}?pageToken={cursor}"), StatusCode::FORBIDDEN).await?;
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and owned store fault"]
async fn pg_organizations_audit_history_http_size_bound_and_store_recovery() -> ManagementTestResult
{
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let h = Harness::new(&pool).await?;
        let path = format!("{}/audit-events", h.collection.trim_end_matches("/organizations"));
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"export\"]',revision=revision+1 WHERE domain_id=$1 AND administrator_id=$2")
            .bind(h.domain).bind(h.administrator).execute(&pool).await?;
        page(&h, &path, StatusCode::OK).await?;
        let admin = crate::web::test_support::test_admin_pool(&pool).await?;
        let role: String = sqlx::query_scalar("SELECT current_user::text").fetch_one(&pool).await?;
        let role = role.replace('"', "\"\"");
        sqlx::query(&format!("REVOKE SELECT ON aegaeon.organization_authority_events FROM \"{role}\"" )).execute(&admin).await?;
        let failed = page(&h, &path, StatusCode::SERVICE_UNAVAILABLE).await;
        sqlx::query(&format!("GRANT SELECT ON aegaeon.organization_authority_events TO \"{role}\"" )).execute(&admin).await?;
        failed?;
        page(&h, &path, StatusCode::OK).await?;
        sqlx::query("INSERT INTO aegaeon.organization_authority_events(id,environment_id,domain_id,actor_id,actor_kind,client_id,request_id,reason,event_type,data) VALUES($1,$2,$3,$4,'operator','audit-fixture','bounded','retained malformed imported event','domain.fixture_oversized',jsonb_build_object('value',repeat('x',65537)))")
            .bind(Uuid::from_u128(1)).bind(h.environment).bind(h.domain).bind(h.administrator).execute(&pool).await?;
        page(&h, &path, StatusCode::SERVICE_UNAVAILABLE).await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE id=$1")
            .bind(Uuid::from_u128(1)).fetch_one(&pool).await?;
        assert_eq!(count, 1, "the unsupported row is retained, never skipped or deleted");
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
