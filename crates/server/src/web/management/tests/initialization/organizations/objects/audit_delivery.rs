use super::*;
mod replay;

async fn setup(
    pool: &sqlx::PgPool,
) -> Result<(Harness, String, String), Box<dyn std::error::Error>> {
    let h = Harness::new(pool).await?;
    let base = format!(
        "{}/audit-events",
        h.collection.trim_end_matches("/organizations")
    );
    let pending = format!("{base}/pending");
    let ack = format!("{base}/acknowledgments");
    assert_eq!(
        h.app.clone().oneshot(h.read(&pending)).await?.status(),
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"export\"]',revision=revision+1 WHERE domain_id=$1 AND administrator_id=$2")
        .bind(h.domain).bind(h.administrator).execute(pool).await?;
    Ok((h, pending, ack))
}

fn acknowledgment(batch: &Value) -> Value {
    let events: Vec<_> = batch["deliveries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| json!({"id":d["event"]["id"],"sha256":d["sha256"]}))
        .collect();
    json!({"events":events,"reason":"durable receiver custody"})
}

async fn delivered(pool: &sqlx::PgPool, domain: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_outbox o JOIN aegaeon.organization_authority_events e ON e.id=o.event_id WHERE e.domain_id=$1 AND o.delivered_at IS NOT NULL")
        .bind(domain).fetch_one(pool).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_audit_delivery_http_batch_current_authority_and_replay(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let (h, pending, ack) = setup(&pool).await?;
        let (batch, tag) = representation(h.app.clone().oneshot(h.read(&pending)).await?,StatusCode::OK).await?;
        assert_eq!(batch["version"],1);
        assert_eq!(batch["domainId"],h.domain.to_string());
        let input = acknowledgment(&batch);
        let count = input["events"].as_array().ok_or("events")?.len();
        assert!(count > 0);
        for (value, status) in [(None,StatusCode::PRECONDITION_REQUIRED),(Some("*"),StatusCode::PRECONDITION_REQUIRED),(Some("W/\"audit-batch.invalid\""),StatusCode::BAD_REQUEST),(Some("\"support-policy.invalid\""),StatusCode::BAD_REQUEST)] {
            assert_eq!(h.app.clone().oneshot(mutation(&ack,Method::POST,input.clone(),&h.cookie,"ack",value)).await?.status(),status);
        }
        let mut request = mutation(&ack,Method::POST,input.clone(),&h.cookie,"ack",Some(&tag));
        request.headers_mut().remove("x-csrf-token");
        assert_eq!(h.app.clone().oneshot(request).await?.status(),StatusCode::FORBIDDEN);
        let mut bad = input.clone(); bad["events"][0]["sha256"] = "0".repeat(64).into();
        assert_eq!(h.app.clone().oneshot(mutation(&ack,Method::POST,bad,&h.cookie,"ack",Some(&tag))).await?.status(),StatusCode::PRECONDITION_FAILED);
        let foreign = ack.replace(&h.domain.to_string(), &Uuid::new_v4().to_string());
        assert_eq!(h.app.clone().oneshot(mutation(&foreign,Method::POST,input.clone(),&h.cookie,"ack",Some(&tag))).await?.status(),StatusCode::FORBIDDEN);
        assert_eq!(delivered(&pool,h.domain).await?,0);
        let request = || mutation(&ack,Method::POST,input.clone(),&h.cookie,"ack",Some(&tag));
        let (a,b) = tokio::join!(h.app.clone().oneshot(request()),h.app.clone().oneshot(request()));
        let (receipt, _) = representation(a?,StatusCode::OK).await?;
        assert_eq!(representation(b?,StatusCode::OK).await?.0,receipt);
        assert_eq!(receipt["events"], input["events"]);
        assert_eq!(receipt["actorId"],h.administrator.to_string());
        assert!(!receipt["requestId"].as_str().ok_or("request id")?.is_empty());
        assert_eq!(delivered(&pool,h.domain).await?,count as i64);
        let (empty,_) = representation(h.app.clone().oneshot(h.read(&pending)).await?,StatusCode::OK).await?;
        assert!(empty["deliveries"].as_array().ok_or("deliveries")?.is_empty());
        assert_eq!(h.app.clone().oneshot(mutation(&ack,Method::POST,input.clone(),&h.cookie,"different-key",Some(&tag))).await?.status(),StatusCode::PRECONDITION_FAILED);
        let mut changed = input.clone(); changed["reason"]="different request".into();
        assert_eq!(h.app.clone().oneshot(mutation(&ack,Method::POST,changed,&h.cookie,"ack",Some(&tag))).await?.status(),StatusCode::CONFLICT);
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE domain_id=$1").bind(h.domain).fetch_one(&pool).await?;
        assert_eq!(events,count as i64,"acknowledgment neither deletes history nor creates recursive delivery");
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false,revision=revision+1 WHERE domain_id=$1 AND administrator_id=$2")
            .bind(h.domain).bind(h.administrator).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(request()).await?.status(),StatusCode::FORBIDDEN);
        assert_eq!(h.app.clone().oneshot(h.read(&pending)).await?.status(),StatusCode::FORBIDDEN);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and owned store fault"]
async fn pg_organizations_audit_delivery_http_atomic_fault_recovery_and_race(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let (h, pending, ack) = setup(&pool).await?;
        let (batch, tag) = representation(h.app.clone().oneshot(h.read(&pending)).await?,StatusCode::OK).await?;
        let input = acknowledgment(&batch);
        let admin = crate::web::test_support::test_admin_pool(&pool).await?;
        let role: String = sqlx::query_scalar("SELECT current_user::text").fetch_one(&pool).await?;
        let role = role.replace('"',"\"\"");
        sqlx::query(&format!("REVOKE INSERT ON aegaeon.organization_authority_receipts FROM \"{role}\"" )).execute(&admin).await?;
        let failed = h.app.clone().oneshot(mutation(&ack,Method::POST,input.clone(),&h.cookie,"fault",Some(&tag))).await;
        sqlx::query(&format!("GRANT INSERT ON aegaeon.organization_authority_receipts TO \"{role}\"" )).execute(&admin).await?;
        assert_eq!(failed?.status(),StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(delivered(&pool,h.domain).await?,0,"outbox update rolls back when immutable receipt fails");
        assert_eq!(representation(h.app.clone().oneshot(h.read(&pending)).await?,StatusCode::OK).await?.1,tag);
        let request = |key| mutation(&ack,Method::POST,input.clone(),&h.cookie,key,Some(&tag));
        let (a,b) = tokio::join!(h.app.clone().oneshot(request("fault")),h.app.clone().oneshot(request("competing")));
        let statuses=[a?.status(),b?.status()];
        assert!(statuses.contains(&StatusCode::OK));
        assert!(statuses.contains(&StatusCode::PRECONDITION_FAILED));
        let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_receipts WHERE domain_id=$1 AND operation='audit.delivery.acknowledge'").bind(h.domain).fetch_one(&pool).await?;
        assert_eq!(receipts,1);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_audit_delivery_http_receipt_capacity_preserves_history(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let (h, pending, ack) = setup(&pool).await?;
        let (batch, tag) = representation(h.app.clone().oneshot(h.read(&pending)).await?,StatusCode::OK).await?;
        sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result) SELECT $1,$2,$3,'operator','management-console',$4,'audit.delivery.acknowledge',n::text,decode(repeat('00',32),'hex'),'{}' FROM generate_series(1,$5) n")
            .bind(h.environment).bind(h.domain).bind(h.administrator).bind(Uuid::nil()).bind(crate::organizations::audit::retention::MAX_EVENTS).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(mutation(&ack,Method::POST,acknowledgment(&batch),&h.cookie,"full",Some(&tag))).await?.status(),StatusCode::CONFLICT);
        assert_eq!(delivered(&pool,h.domain).await?,0);
        assert_eq!(representation(h.app.clone().oneshot(h.read(&pending)).await?,StatusCode::OK).await?.0,batch);
        assert_eq!(h.app.clone().oneshot(h.read(pending.trim_end_matches("/pending"))).await?.status(),StatusCode::OK);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
