use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_targets_require_configuration_authority_and_preserve_exact_audiences(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
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
        assert_eq!(registered["enabled"], false);
        assert_eq!(registered["revision"], 2);
        assert_eq!(
            registered["targets"],
            json!([{"audience":"urn:example:学校/É","management":false,"introspectionClients":[]}])
        );
        assert_eq!(
            representation(
                app.clone()
                    .oneshot(mutation(
                        &targets,
                        Method::POST,
                        body.clone(),
                        &cookie,
                        "target",
                        Some(&tag)
                    ))
                    .await?,
                StatusCode::OK
            )
            .await?,
            (registered.clone(), next_tag.clone())
        );
        assert_eq!(
            app.clone()
                .oneshot(mutation(
                    &targets,
                    Method::POST,
                    body.clone(),
                    &cookie,
                    "stale",
                    Some(&tag)
                ))
                .await?
                .status(),
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(
            app.clone()
                .oneshot(mutation(
                    &targets,
                    Method::POST,
                    body.clone(),
                    &cookie,
                    "duplicate",
                    Some(&next_tag)
                ))
                .await?
                .status(),
            StatusCode::CONFLICT
        );
        for invalid in [
            json!({"audience":"urn:new","reason":"missing explicit purpose"}),
            json!({"audience":"urn:new","management":false,"reason":"unknown","enabled":true}),
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(mutation(
                        &targets,
                        Method::POST,
                        invalid,
                        &cookie,
                        "invalid",
                        Some(&next_tag)
                    ))
                    .await?
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            app.clone()
                .oneshot(read(&format!("{path}?unknown=1")))
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            representation(app.clone().oneshot(read(&path)).await?, StatusCode::OK).await?,
            (registered, next_tag)
        );
        sqlx::query(
            "UPDATE aegaeon.organization_operator_grants SET active=false WHERE domain_id=$1",
        )
        .bind(Uuid::parse_str(domain_id)?)
        .execute(&pool)
        .await?;
        assert_eq!(
            app.clone().oneshot(read(&path)).await?.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.oneshot(mutation(
                &targets,
                Method::POST,
                body,
                &cookie,
                "target",
                Some(&tag)
            ))
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}
