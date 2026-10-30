use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL; actual scoped HTTP creation"]
async fn pg_organizations_http_equal_external_ids_remain_separate_between_domains(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let h = Harness::new(&pool).await?;
        let external = "学校/É #?same";
        let (first, _) = representation(h.app.clone().oneshot(h.create(external, "same")).await?, StatusCode::OK).await?;
        // The second enabled domain is fixture supply. Its operator still needs
        // an independent explicit grant before using the mounted creation API.
        let domain = Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.authorization_domains(id,environment_id,name,enabled) VALUES($1,$2,'second fixture',true)").bind(domain).bind(h.environment).execute(&pool).await?;
        let second = Harness { app:h.app.clone(), cookie:h.cookie.clone(), collection:h.collection.replace(&h.domain.to_string(),&domain.to_string()), domain, environment:h.environment, administrator:h.administrator };
        assert_eq!(second.app.clone().oneshot(second.create(external,"same")).await?.status(), StatusCode::FORBIDDEN);
        crate::organizations::request_work::Admission::drain_for_test().await?;
        sqlx::query("INSERT INTO aegaeon.organization_operator_grants(id,environment_id,domain_id,administrator_id,active,capabilities) VALUES($1,$2,$3,$4,true,'[\"provision\",\"reconcile\"]')").bind(Uuid::new_v4()).bind(h.environment).bind(domain).bind(h.administrator).execute(&pool).await?;
        let (other, _) = representation(second.app.clone().oneshot(second.create(external,"same")).await?,StatusCode::OK).await?;
        assert_eq!(first["externalId"],other["externalId"]);
        assert_ne!(first["id"],other["id"]);
        for (h,foreign,own) in [(&h,&other,&first),(&second,&first,&other)] {
            let foreign_path=format!("{}/{}",h.collection,foreign["id"].as_str().ok_or("foreign id")?);
            assert_eq!(h.app.clone().oneshot(h.read(&foreign_path)).await?.status(),StatusCode::FORBIDDEN);
            let response=h.app.clone().oneshot(h.read(&h.collection)).await?;
            assert_eq!(response.status(),StatusCode::OK);
            let data:Value=serde_json::from_slice(&body::to_bytes(response.into_body(),65_536).await?)?;
            assert_eq!(data["organizations"],json!([own]));
        }
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and privileged fixture-only outbox fault"]
async fn pg_organizations_http_outbox_failure_rolls_back_and_identity_quota_retains_restriction(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let admin = crate::web::test_support::test_admin_pool(&pool).await?;
    let result:ManagementTestResult=async {
        let h=Harness::new(&pool).await?;
        let before:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.organization_authority_events),(SELECT count(*) FROM aegaeon.organization_authority_outbox),(SELECT count(*) FROM aegaeon.organization_authority_receipts)").fetch_one(&pool).await?;
        sqlx::raw_sql("CREATE FUNCTION aegaeon.provisioning_outbox_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture outbox failure'; END $$; CREATE TRIGGER provisioning_outbox_fault BEFORE INSERT ON aegaeon.organization_authority_outbox FOR EACH ROW EXECUTE FUNCTION aegaeon.provisioning_outbox_fault()").execute(&admin).await?;
        let failed=h.app.clone().oneshot(h.create("transactional","creation")).await?;
        assert_eq!(failed.status(),StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(failed.headers()["cache-control"],"no-store");
        crate::organizations::request_work::Admission::drain_for_test().await?;
        let after:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.organization_authority_events),(SELECT count(*) FROM aegaeon.organization_authority_outbox),(SELECT count(*) FROM aegaeon.organization_authority_receipts)").fetch_one(&pool).await?;
        assert_eq!(before,after);
        let objects:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.application_organizations WHERE domain_id=$1").bind(h.domain).fetch_one(&pool).await?;
        assert_eq!(objects,0);
        sqlx::raw_sql("DROP TRIGGER provisioning_outbox_fault ON aegaeon.organization_authority_outbox; DROP FUNCTION aegaeon.provisioning_outbox_fault()").execute(&admin).await?;
        let (created,tag)=representation(h.app.clone().oneshot(h.create("transactional","creation")).await?,StatusCode::OK).await?;
        let id=Uuid::parse_str(created["id"].as_str().ok_or("id")?)?;
        // Manufacture retained tombstones to reach the exact identity limit.
        // These rows do not claim historical audit or invitation acceptance.
        sqlx::query("INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state) SELECT gen_random_uuid(),$1,$2,'quota-'||i,'deleted' FROM generate_series(1,1023) i").bind(h.environment).bind(h.domain).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(h.create("excess","excess")).await?.status(),StatusCode::CONFLICT);
        assert_eq!(representation(h.app.clone().oneshot(h.create("transactional","creation")).await?,StatusCode::OK).await?,(created,tag.clone()));
        // State supply isolates the mounted restrictive transition; activation
        // is not exposed by this fixture or the operator API.
        sqlx::query("UPDATE aegaeon.application_organizations SET state='active' WHERE id=$1").bind(id).execute(&pool).await?;
        let item=format!("{}/{id}",h.collection);
        let (suspended,tag)=representation(h.app.clone().oneshot(mutation(&format!("{item}/suspend"),Method::POST,json!({"reason":"restrict"}),&h.cookie,"suspend",Some(&tag))).await?,StatusCode::OK).await?;
        assert_eq!(suspended["state"],"suspended");
        let (deleted,_)=representation(h.app.clone().oneshot(mutation(&format!("{item}/delete"),Method::POST,json!({"reason":"retire"}),&h.cookie,"delete",Some(&tag))).await?,StatusCode::OK).await?;
        assert_eq!(deleted["state"],"deleted");
        assert_eq!(h.app.clone().oneshot(h.create("still-excess","still-excess")).await?.status(),StatusCode::CONFLICT);
        let objects:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.application_organizations WHERE domain_id=$1").bind(h.domain).fetch_one(&pool).await?;
        assert_eq!(objects,1024);
        Ok(())
    }.await;
    admin.close().await;
    finish(result, cleanup(control, pool, &name).await)
}
