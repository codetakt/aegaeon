use super::*;
use axum::body::to_bytes;
use tokio_stream::StreamExt;
mod epoch;

fn path(h: &Harness) -> String {
    format!(
        "{}/snapshot",
        h.collection.trim_end_matches("/organizations")
    )
}

async fn grant(h: &Harness, pool: &sqlx::PgPool) -> ManagementTestResult {
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"export\"]',revision=revision+1 WHERE domain_id=$1 AND administrator_id=$2")
        .bind(h.domain).bind(h.administrator).execute(pool).await?;
    Ok(())
}

async fn prefix(body: Body) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) =
        tokio::time::timeout(std::time::Duration::from_secs(35), stream.next()).await?
    {
        let Ok(chunk) = chunk else {
            break;
        };
        bytes.extend(chunk);
        assert!(bytes.len() < 2 * 1024 * 1024);
    }
    Ok(bytes)
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; actual HTTP MVCC transfer and scope authorization"]
async fn pg_organizations_snapshot_http_consistent_exact_ids_and_authorization(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let h=Harness::new(&pool).await?;let path=path(&h);
        assert_eq!(h.app.clone().oneshot(Request::builder().uri(&path).body(Body::empty())?).await?.status(),StatusCode::UNAUTHORIZED);
        crate::organizations::request_work::Admission::drain_for_test().await?;
        assert_eq!(h.app.clone().oneshot(h.read(&path)).await?.status(),StatusCode::FORBIDDEN);
        crate::organizations::request_work::Admission::drain_for_test().await?;
        let mut ids=Vec::new();
        for (index,id) in ["School","school","É","E\u{301}","urn:学校/opaque"].iter().enumerate() {
            let (created,_)=representation(h.app.clone().oneshot(h.create(id,&format!("snapshot-{index}"))).await?,StatusCode::OK).await?;
            ids.push(created["id"].as_str().ok_or("id")?.to_owned());
        }
        grant(&h,&pool).await?;
        for query in ["unexpected=true","version=1"] {
            assert_eq!(h.app.clone().oneshot(h.read(&format!("{path}?{query}"))).await?.status(),StatusCode::BAD_REQUEST);
        }
        let foreign=path.replace(&h.domain.to_string(),&Uuid::new_v4().to_string());
        assert_eq!(h.app.clone().oneshot(h.read(&foreign)).await?.status(),StatusCode::FORBIDDEN);
        crate::organizations::request_work::Admission::drain_for_test().await?;
        let head=h.app.clone().oneshot(Request::builder().method(Method::HEAD).uri(&path).header("cookie",&h.cookie).body(Body::empty())?).await?;
        assert_eq!(head.status(),StatusCode::OK);assert!(to_bytes(head.into_body(),4096).await?.is_empty());
        let response=h.app.clone().oneshot(h.read(&path)).await?;
        assert_eq!(response.status(),StatusCode::OK);assert_eq!(response.headers()["cache-control"],"no-store");
        assert_eq!(response.headers()["content-type"],"application/x-ndjson");
        sqlx::query("UPDATE aegaeon.application_organizations SET state='suspended',revision=revision+1 WHERE id=$1")
            .bind(Uuid::parse_str(&ids[0])?).execute(&pool).await?;
        let bytes=prefix(response.into_body()).await?;
        let text=std::str::from_utf8(&bytes)?;
        let rows=text.lines().map(serde_json::from_str::<Value>).collect::<Result<Vec<_>,_>>()?;
        assert_eq!(rows[0]["record"],"header");assert_eq!(rows.last().ok_or("manifest")?["record"],"manifest");
        let orgs=rows.iter().filter(|r|r["section"]=="organizations").collect::<Vec<_>>();
        assert_eq!(orgs.len(),5);
        for org in orgs { assert_eq!(org["data"]["state"],"provisioning"); }
        let external=rows.iter().filter(|r|r["section"]=="organizations").map(|r|r["data"]["external_id"].as_str().ok_or("external id")).collect::<Result<std::collections::BTreeSet<_>,_>>()?;
        assert_eq!(external,std::collections::BTreeSet::from(["School","school","É","E\u{301}","urn:学校/opaque"]));
        println!("SNAPSHOT_HTTP_FIXTURE_START\n{text}SNAPSHOT_HTTP_FIXTURE_END");
        crate::organizations::request_work::Admission::drain_for_test().await?;
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; revocation during a backpressured HTTP transfer"]
async fn pg_organizations_snapshot_http_revocation_stops_disclosure_and_releases_admission(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let h=Harness::new(&pool).await?;grant(&h,&pool).await?;let path=path(&h);
        let response=h.app.clone().oneshot(h.read(&path)).await?;
        assert_eq!(response.status(),StatusCode::OK);
        // Header fills the only output slot; no data page has been admitted.
        assert_eq!(h.app.clone().oneshot(h.read(&path)).await?.status(),StatusCode::SERVICE_UNAVAILABLE);
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false,revision=revision+1 WHERE domain_id=$1 AND administrator_id=$2")
            .bind(h.domain).bind(h.administrator).execute(&pool).await?;
        let bytes=prefix(response.into_body()).await?;
        let rows=std::str::from_utf8(&bytes)?.lines().map(serde_json::from_str::<Value>).collect::<Result<Vec<_>,_>>()?;
        assert_eq!(rows.len(),1,"revoked transfer must disclose no data pages or manifest");assert_eq!(rows[0]["record"],"header");
        crate::organizations::request_work::Admission::drain_for_test().await?;
        assert_eq!(h.app.clone().oneshot(h.read(&path)).await?.status(),StatusCode::FORBIDDEN);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and owned store permission fault"]
async fn pg_organizations_snapshot_http_cancel_store_failure_and_recovery() -> ManagementTestResult
{
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let h = Harness::new(&pool).await?;
        grant(&h, &pool).await?;
        let path = path(&h);
        let response = h.app.clone().oneshot(h.read(&path)).await?;
        assert_eq!(response.status(), StatusCode::OK);
        drop(response);
        crate::organizations::request_work::Admission::drain_for_test().await?;
        let admin = crate::web::test_support::test_admin_pool(&pool).await?;
        let role: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&pool)
            .await?;
        let role = role.replace('"', "\"\"");
        let response = h.app.clone().oneshot(h.read(&path)).await?;
        assert_eq!(response.status(), StatusCode::OK);
        sqlx::query(&format!(
            "REVOKE SELECT ON aegaeon.organization_authority_events FROM \"{role}\""
        ))
        .execute(&admin)
        .await?;
        let failed = prefix(response.into_body()).await;
        sqlx::query(&format!(
            "GRANT SELECT ON aegaeon.organization_authority_events TO \"{role}\""
        ))
        .execute(&admin)
        .await?;
        let text = String::from_utf8(failed?)?;
        assert!(!text.contains("\"record\":\"manifest\""));
        crate::organizations::request_work::Admission::drain_for_test().await?;
        let recovered = h.app.clone().oneshot(h.read(&path)).await?;
        assert_eq!(recovered.status(), StatusCode::OK);
        let text = String::from_utf8(prefix(recovered.into_body()).await?)?;
        assert!(text.contains("\"record\":\"manifest\""));
        crate::organizations::request_work::Admission::drain_for_test().await?;
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; actual bounded slow receiver and connection cleanup"]
async fn pg_organizations_snapshot_http_stalled_receiver_releases_owned_connections(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let h = Harness::new(&pool).await?;
        grant(&h, &pool).await?;
        let path = path(&h);
        let started = tokio::time::Instant::now();
        let response = h.app.clone().oneshot(h.read(&path)).await?;
        assert_eq!(response.status(), StatusCode::OK);
        // Keep the body alive without polling it. The production progress
        // deadline, not client cancellation, must end the worker and SQL work.
        tokio::time::timeout(
            std::time::Duration::from_secs(25),
            crate::organizations::request_work::Admission::drain_for_test(),
        )
        .await??;
        let text = String::from_utf8(prefix(response.into_body()).await?)?;
        assert!(text.contains("\"record\":\"header\""));
        assert!(!text.contains("\"record\":\"manifest\""));
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
        let recovered = h.app.clone().oneshot(h.read(&path)).await?;
        assert_eq!(recovered.status(), StatusCode::OK);
        assert!(String::from_utf8(prefix(recovered.into_body()).await?)?
            .contains("\"record\":\"manifest\""));
        crate::organizations::request_work::Admission::drain_for_test().await?;
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}
