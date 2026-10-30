use super::*;

fn roles() -> Value {
    json!([
        {"key":"reader","privileges":["read"],"managesMembers":false,"assignableRoles":[]},
        {"key":"manager","privileges":["organization.members.manage","read"],"managesMembers":true,"assignableRoles":["manager","reader"]}
    ])
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and authenticated management HTTP"]
async fn pg_organizations_http_role_policy_versions_replay_and_current_capability(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let h=Harness::new(&pool).await?;
        let path=format!("{}/role-policy",h.collection.strip_suffix("/organizations").ok_or("path")?);
        let (empty,tag)=representation(h.app.clone().oneshot(h.read(&path)).await?,StatusCode::OK).await?;
        assert_eq!(empty,json!({"id":h.domain,"revision":1,"roles":[]}));
        assert_eq!(tag,format!("\"role-policy.{}.1\"",h.domain));
        let payload=json!({"roles":roles(),"reason":"define vocabulary"});
        let put=|value:Value,key:&str,tag:&str|mutation(&path,Method::PUT,value,&h.cookie,key,Some(tag));
        let (left,right)=tokio::join!(h.app.clone().oneshot(put(payload.clone(),"initial",&tag)),h.app.clone().oneshot(put(payload.clone(),"initial",&tag)));
        let (first,first_tag)=representation(left?,StatusCode::OK).await?;
        assert_eq!(representation(right?,StatusCode::OK).await?,(first.clone(),first_tag.clone()));
        assert_eq!(first["revision"],3);
        assert!(first["roles"].as_array().ok_or("roles")?.iter().all(|role|role["version"]==1));
        assert_eq!(h.app.clone().oneshot(put(payload.clone(),"stale",&tag)).await?.status(),StatusCode::PRECONDITION_FAILED);
        assert_eq!(h.app.clone().oneshot(put(payload.clone(),"wrong-type",&format!("\"{}.3\"",h.domain))).await?.status(),StatusCode::BAD_REQUEST);
        for (key,invalid) in [
            ("duplicate",json!([roles()[0],roles()[0],roles()[1]])),
            ("missing-retained",json!([roles()[0]])),
            ("unknown-assigned",json!([{ "key":"manager","privileges":["read"],"managesMembers":true,"assignableRoles":["unknown"]},roles()[0]])),
        ] {
            assert_eq!(h.app.clone().oneshot(put(json!({"roles":invalid,"reason":"invalid"}),key,&first_tag)).await?.status(),StatusCode::BAD_REQUEST);
            crate::organizations::request_work::Admission::drain_for_test().await?;
        }
        let domain_revision:i64=sqlx::query_scalar("SELECT revision FROM aegaeon.authorization_domains WHERE id=$1").bind(h.domain).fetch_one(&pool).await?;
        let mut changed=roles();changed[1]["privileges"]=json!(["organization.members.manage","read","write"]);
        let (next,_)=representation(h.app.clone().oneshot(put(json!({"roles":changed,"reason":"change meaning"}),"change",&first_tag)).await?,StatusCode::OK).await?;
        assert_eq!(next["revision"],4);
        for role in next["roles"].as_array().ok_or("roles")? {assert_eq!(role["version"],if role["key"]=="manager" {2}else{1});}
        let after:i64=sqlx::query_scalar("SELECT revision FROM aegaeon.authorization_domains WHERE id=$1").bind(h.domain).fetch_one(&pool).await?;
        assert_eq!(after,domain_revision,"role meaning must not change unrelated domain activation generation");
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"provision\",\"reconcile\"]' WHERE domain_id=$1").bind(h.domain).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(h.read(&path)).await?.status(),StatusCode::FORBIDDEN);
        assert_eq!(h.app.clone().oneshot(put(payload,"initial",&tag)).await?.status(),StatusCode::FORBIDDEN);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
