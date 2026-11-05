use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_audit_delivery_http_uncertain_commit_rechecks_export_on_replay(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let (h, pending, ack) = setup(&pool).await?;
        let (batch, tag) = representation(h.app.clone().oneshot(h.read(&pending)).await?,StatusCode::OK).await?;
        let input = acknowledgment(&batch);
        let request = || mutation(&ack,Method::POST,input.clone(),&h.cookie,"uncertain",Some(&tag));
        // The committed response is deliberately discarded, as after a lost reply.
        let response = h.app.clone().oneshot(request()).await?;
        assert_eq!(response.status(),StatusCode::OK);
        drop(response);
        let stored: Value = sqlx::query_scalar("SELECT result FROM aegaeon.organization_authority_receipts WHERE domain_id=$1 AND operation='audit.delivery.acknowledge' AND idempotency_key='uncertain'")
            .bind(h.domain).fetch_one(&pool).await?;
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"reconcile\"]',revision=revision+1 WHERE domain_id=$1 AND administrator_id=$2")
            .bind(h.domain).bind(h.administrator).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(request()).await?.status(),StatusCode::FORBIDDEN);
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"export\"]',revision=revision+1 WHERE domain_id=$1 AND administrator_id=$2")
            .bind(h.domain).bind(h.administrator).execute(&pool).await?;
        let (replayed, _) = representation(h.app.clone().oneshot(request()).await?,StatusCode::OK).await?;
        assert_eq!(replayed,stored,"original receipt survives policy changes without restoring old authority");
        assert_eq!(delivered(&pool,h.domain).await?,input["events"].as_array().ok_or("events")?.len() as i64);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
