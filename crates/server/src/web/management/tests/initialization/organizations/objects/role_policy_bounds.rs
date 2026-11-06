use super::*;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; large legitimate policy and actual audit API"]
async fn pg_organizations_http_large_role_policy_retains_readable_audit_versions(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let h = Harness::new(&pool).await?;
        let domain = h.collection.strip_suffix("/organizations").ok_or("path")?;
        let path = format!("{domain}/role-policy");
        let (_, mut tag) = representation(h.app.clone().oneshot(h.read(&path)).await?, StatusCode::OK).await?;
        let mut versions = Vec::new();
        for revision in 0..2 {
            let roles: Vec<Value> = (0..2).map(|role| {
                let privileges: Vec<String> = (0..170).map(|i| format!("p{revision}{i:03}{}", "a".repeat(120))).collect();
                json!({"key":format!("role{role}"),"privileges":privileges,"managesMembers":false,"assignableRoles":[]})
            }).collect();
            let payload = json!({"roles":roles,"reason":"large supported configuration"});
            let size = serde_json::to_vec(&payload)?.len();
            assert!((40 * 1024..48 * 1024).contains(&size));
            let (value, new_tag) = representation(h.app.clone().oneshot(mutation(&path,Method::PUT,payload,&h.cookie,&format!("large-{revision}"),Some(&tag))).await?, StatusCode::OK).await?;
            assert_eq!(value["roles"].as_array().ok_or("roles")?.len(),2);
            versions.push(value["revision"].clone());
            tag = new_tag;
        }
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"configure\",\"export\"]',revision=revision+1 WHERE domain_id=$1 AND administrator_id=$2")
            .bind(h.domain).bind(h.administrator).execute(&pool).await?;
        let response = h.app.clone().oneshot(h.read(&format!("{domain}/audit-events"))).await?;
        assert_eq!(response.status(),StatusCode::OK);
        let page:Value = serde_json::from_slice(&body::to_bytes(response.into_body(),65_536).await?)?;
        let events:Vec<_> = page["events"].as_array().ok_or("events")?.iter().filter(|v|v["eventType"]=="domain.role_policy.replace").collect();
        assert_eq!(events.len(),2);
        let event = events.iter().find(|v|v["data"]["after"]["revision"]==versions[1]).ok_or("second version")?;
        assert_eq!(event["data"]["before"]["revision"],versions[0]);
        assert_eq!(event["data"]["after"]["roles"],json!({"role0":2,"role1":2}));
        assert_eq!(event["data"]["authorityBasis"]["kind"],"domain_operator");
        assert!(!event.to_string().contains("privileges"));
        assert!(serde_json::to_vec(&page)?.len() < 64 * 1024);
        let (pending, _) = representation(h.app.clone().oneshot(h.read(&format!("{domain}/audit-events/pending"))).await?, StatusCode::OK).await?;
        assert_eq!(pending["deliveries"].as_array().ok_or("pending events")?.len(), page["events"].as_array().ok_or("history events")?.len());
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; competing HTTP CAS and retained budget fixtures"]
async fn pg_organizations_http_role_policy_cas_bounds_preserve_disable() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let h = Harness::new(&pool).await?;
        let domain = h.collection.strip_suffix("/organizations").ok_or("path")?;
        let path = format!("{domain}/role-policy");
        let (_, empty_tag) = representation(h.app.clone().oneshot(h.read(&path)).await?, StatusCode::OK).await?;
        let roles = json!([{ "key":"reader","privileges":["read"],"managesMembers":false,"assignableRoles":[] }]);
        let payload = json!({"roles":roles,"reason":"initial"});
        let put = |value:Value,key:&str,tag:&str| mutation(&path,Method::PUT,value,&h.cookie,key,Some(tag));
        let (first, tag) = representation(h.app.clone().oneshot(put(payload.clone(),"initial",&empty_tag)).await?, StatusCode::OK).await?;
        let mut oversized = Vec::new();
        for index in 0..2 {
            let privileges: Vec<String> = (0..200).map(|i| format!("p{i:03}{}", "a".repeat(120))).collect();
            oversized.push(json!({"key":format!("role{index}"),"privileges":privileges,"managesMembers":false,"assignableRoles":[]}));
        }
        let bounded_input = json!({"roles":oversized,"reason":"catalog over 48 KiB"});
        assert!(serde_json::to_vec(&bounded_input)?.len() < 64 * 1024);
        assert_eq!(h.app.clone().oneshot(put(bounded_input,"too-large",&tag)).await?.status(), StatusCode::CONFLICT);
        assert_eq!(representation(h.app.clone().oneshot(h.read(&path)).await?,StatusCode::OK).await?,(first.clone(),tag.clone()));
        let change = |privilege:&str| json!({"roles":[{"key":"reader","privileges":["read",privilege],"managesMembers":false,"assignableRoles":[]}],"reason":"competing edit"});
        let (left,right) = tokio::join!(h.app.clone().oneshot(put(change("write"),"left",&tag)),h.app.clone().oneshot(put(change("list"),"right",&tag)));
        let statuses = [left?.status(),right?.status()];
        assert_eq!(statuses.iter().filter(|v| **v==StatusCode::OK).count(),1);
        assert_eq!(statuses.iter().filter(|v| **v==StatusCode::PRECONDITION_FAILED).count(),1);
        let (current,current_tag) = representation(h.app.clone().oneshot(h.read(&path)).await?,StatusCode::OK).await?;
        assert_eq!(current["revision"],3);
        // Retained receipts are supplied only to exercise the exact quota.
        let count:i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_receipts WHERE domain_id=$1 AND operation LIKE 'domain.%'").bind(h.domain).fetch_one(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,operation,idempotency_key,request_digest,result,client_registration_id) SELECT $1,$2,$3,'operator','management-console','domain.fixture','capacity-'||i,decode(repeat('00',32),'hex'),'{}'::jsonb,'00000000-0000-0000-0000-000000000000'::uuid FROM generate_series(1,$4) i")
            .bind(h.environment).bind(h.domain).bind(h.administrator).bind(10_000-count).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(put(change("export"),"exhausted",&current_tag)).await?.status(),StatusCode::CONFLICT);
        assert_eq!(representation(h.app.clone().oneshot(put(payload,"initial",&empty_tag)).await?,StatusCode::OK).await?,(first,tag));
        let (_,domain_tag) = representation(h.app.clone().oneshot(h.read(domain)).await?,StatusCode::OK).await?;
        let (disabled,_) = representation(h.app.clone().oneshot(mutation(&format!("{domain}/disable"),Method::POST,json!({"reason":"emergency restriction"}),&h.cookie,"disable",Some(&domain_tag))).await?,StatusCode::OK).await?;
        assert_eq!(disabled["enabled"],false);
        // Counter exhaustion is manufactured independently of receipt history.
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET version=$1 WHERE domain_id=$2").bind(i64::MAX-1).bind(h.domain).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(h.read(&path)).await?.status(),StatusCode::CONFLICT);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
