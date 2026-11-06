use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_recipients_current_session_scope_and_reserved_revocation(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let initialized = initialize_management(&pool, &input()).await?;
        let mut mgmt = test_management_state();
        mgmt.cfg = Arc::new(
            crate::web::management::ManagementConfig::try_from_env_with_database(&pool).await?,
        );
        let app = crate::web::build_router(test_app_state(pool.clone(), mgmt)?);
        let login = app
            .clone()
            .oneshot(request(
                "/api/v1/authentication/sessions",
                json!({"email":input().owner_email,"password":input().owner_password}),
                "",
                "https://admin.aegaeon.test",
                true,
            ))
            .await?;
        assert_eq!(login.status(), StatusCode::NO_CONTENT);
        let cookie = login
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("aegaeon_admin_session="))
            .ok_or("session")?
            .split(';')
            .next()
            .ok_or("cookie")?
            .to_owned();
        let base = format!(
            "/api/v1/teams/{}/environments/{}/organization-domains",
            initialized.team_id, initialized.environment_id
        );
        let (domain, tag) = representation(
            app.clone()
                .oneshot(mutation(
                    &format!("{base}/default"),
                    Method::POST,
                    json!({"reason":"initialize"}),
                    &cookie,
                    "bootstrap",
                    None,
                ))
                .await?,
            StatusCode::OK,
        )
        .await?;
        let domain_id = domain["id"].as_str().ok_or("domain")?;
        let path = format!("{base}/{domain_id}");
        let targets = format!("{path}/targets");
        let read = |uri: &str| {
            Request::builder()
                .uri(uri)
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap()
        };
        let (before, before_tag) =
            representation(app.clone().oneshot(read(&path)).await?, StatusCode::OK).await?;
        assert_eq!(before_tag, tag);
        assert_eq!(before["enabled"], false);
        assert_eq!(before["targets"], json!([]));
        let body =
            json!({"audience":"urn:example:学校/É","management":false,"reason":"explicit target"});
        for (session, version, status) in [
            ("", Some(tag.as_str()), StatusCode::UNAUTHORIZED),
            (cookie.as_str(), None, StatusCode::PRECONDITION_REQUIRED),
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(mutation(
                        &targets,
                        Method::POST,
                        body.clone(),
                        session,
                        "target",
                        version
                    ))
                    .await?
                    .status(),
                status
            );
        }
        let (registered, next_tag) = representation(
            app.clone()
                .oneshot(mutation(
                    &targets,
                    Method::POST,
                    body.clone(),
                    &cookie,
                    "target",
                    Some(&tag),
                ))
                .await?,
            StatusCode::OK,
        )
        .await?;

        let registration=Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.clients(id,environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method) SELECT $1,id,active_configuration_version_id,'rs-http','RS HTTP','CONFIDENTIAL',ARRAY['https://example.test/cb'],ARRAY['authorization_code'],ARRAY['openid'],'client_secret_basic' FROM aegaeon.environments WHERE id=$2")
            .bind(registration).bind(initialized.environment_id).execute(&pool).await?;
        assert_eq!(registered["targets"][0]["introspectionClients"],json!([]));
        let replace_path=format!("{targets}/introspection-recipients/replace");
        let replace=json!({"audience":"urn:example:学校/É","clientRegistrationIds":[registration],"reason":"explicit RS"});
        for (session,version,status) in [("",Some(next_tag.as_str()),StatusCode::UNAUTHORIZED),(cookie.as_str(),None,StatusCode::PRECONDITION_REQUIRED)] {
            assert_eq!(app.clone().oneshot(mutation(&replace_path,Method::POST,replace.clone(),session,"rs",version)).await?.status(),status);
        }
        let (configured,configured_tag)=representation(app.clone().oneshot(mutation(&replace_path,Method::POST,replace.clone(),&cookie,"rs",Some(&next_tag))).await?,StatusCode::OK).await?;
        assert_eq!(configured["targets"][0]["introspectionClients"],json!([{"clientRegistrationId":registration,"clientIdentifier":"rs-http"}]));
        let mut wrong=replace.clone();wrong["audience"]=json!("urn:example:学校/é");
        assert_eq!(app.clone().oneshot(mutation(&replace_path,Method::POST,wrong,&cookie,"wrong-target",Some(&configured_tag))).await?.status(),StatusCode::FORBIDDEN);
        // Exhaust ordinary admission while preserving the dedicated cancellation path.
        // The preceding refused transaction deliberately retains its lease
        // until asynchronous rollback/protocol cleanup completes.
        let held=tokio::time::timeout(std::time::Duration::from_secs(2),async {
            let mut leases=Vec::new();
            while leases.len()<4 {
                if let Ok(lease)=crate::organizations::request_work::Admission::try_acquire() {
                    leases.push(lease);
                } else {tokio::task::yield_now().await;}
            }
            leases
        }).await?;
        assert_eq!(app.clone().oneshot(mutation(&replace_path,Method::POST,replace.clone(),&cookie,"busy",Some(&configured_tag))).await?.status(),StatusCode::SERVICE_UNAVAILABLE);
        let revoke_path=format!("{targets}/introspection-recipients/revoke");
        let revoke=json!({"audience":"urn:example:学校/É","reason":"remove RS"});
        let (revoked,revoked_tag)=representation(app.clone().oneshot(mutation(&revoke_path,Method::POST,revoke.clone(),&cookie,"revoke-rs",Some(&configured_tag))).await?,StatusCode::OK).await?;
        drop(held);
        assert_eq!(revoked["targets"][0]["introspectionClients"],json!([]));
        let (replayed,_)=representation(app.clone().oneshot(mutation(&replace_path,Method::POST,replace,&cookie,"rs",Some(&next_tag))).await?,StatusCode::OK).await?;
        assert_eq!(replayed,configured);
        let (current,current_tag)=representation(app.clone().oneshot(read(&path)).await?,StatusCode::OK).await?;
        assert_eq!(current,revoked);assert_eq!(current_tag,revoked_tag);
        let mut bad=revoke;bad["clientRegistrationIds"]=json!([registration]);
        assert_eq!(app.clone().oneshot(mutation(&revoke_path,Method::POST,bad,&cookie,"bad",Some(&revoked_tag))).await?.status(),StatusCode::BAD_REQUEST);
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE environment_id=$1").bind(initialized.environment_id).execute(&pool).await?;
        assert_eq!(app.clone().oneshot(mutation(&revoke_path,Method::POST,json!({"audience":"urn:example:学校/É","reason":"remove RS"}),&cookie,"revoke-rs",Some(&configured_tag))).await?.status(),StatusCode::FORBIDDEN);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
