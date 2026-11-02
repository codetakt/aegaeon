use super::*;
use axum::http::header;

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_audit_metadata_is_bounded_and_reports_omissions() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let (app, session) = authenticated_app(&pool).await?;
        let uri = format!("/api/v1/teams/{}/environments/{}/users/{user}/attributes", initialized.team_id, initialized.environment_id);
        for (revision, (count, suffix)) in [
            (1000, "x".repeat(230)), (1000, "あ".repeat(75)),
            (100, "\"".repeat(230)), (3, "small".into()), (0, String::new()),
        ].into_iter().enumerate() {
            let values: serde_json::Map<String, Value> = (0..count)
                .map(|i| (format!("{i:04}-{suffix}"), Value::Null)).collect();
            let revision = i64::try_from(revision)?;
            let payload = json!({"baseRevision":revision,"values":values});
            assert!(serde_json::to_vec(&payload["values"])?.len() < 262_144);
            let mut req = request(&uri, payload, &session, "https://admin.aegaeon.test", true);
            *req.method_mut() = Method::PUT;
            assert_eq!(app.clone().oneshot(req).await?.status(), StatusCode::OK);
            let audit: Value = sqlx::query_scalar("SELECT data FROM aegaeon.audit_events WHERE event_type='management.user.attributes.replaced.v1' AND (data->>'revision')::bigint=$1")
                .bind(revision + 1).fetch_one(&pool).await?;
            let names = audit["attributeNames"].as_array().ok_or("missing audit names")?;
            assert!(names.len() <= 32);
            assert!(serde_json::to_vec(&audit["attributeNames"])?.len() <= 1024);
            assert!(serde_json::to_vec(&audit)?.len() < 2048);
            assert_eq!(audit["attributeNameCount"], json!(count));
            assert_eq!(audit["omittedAttributeNameCount"], json!(count - names.len()));
            assert_eq!(audit["previousRevision"], revision);
            assert_eq!(audit["revision"], revision + 1);
            assert!(names.iter().all(|n| n.as_str().is_some_and(|s| values.contains_key(s))));
            assert_eq!(names.len() == count, count <= 3);
        }
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_browser_can_discover_and_send_conditional_tag() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let (app, session) = authenticated_app(&pool).await?;
        let uri = format!(
            "/api/v1/teams/{}/environments/{}/users/{user}/attributes",
            initialized.team_id, initialized.environment_id
        );
        for origin in ["https://admin.aegaeon.test", "https://untrusted.example"] {
            let req = Request::builder()
                .method(Method::OPTIONS)
                .uri(&uri)
                .header(header::ORIGIN, origin)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "content-type, x-csrf-token, if-match",
                )
                .body(Body::empty())?;
            let response = app.clone().oneshot(req).await?;
            if origin == "https://untrusted.example" {
                assert!(response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none());
            } else {
                assert_eq!(
                    response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
                    origin
                );
                let allowed = response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS].to_str()?;
                assert!(allowed
                    .split(',')
                    .any(|s| s.trim().eq_ignore_ascii_case("if-match")));
                assert_eq!(
                    response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
                    "true"
                );
            }
        }
        let mut req = request(
            &uri,
            Value::Null,
            &session,
            "https://admin.aegaeon.test",
            true,
        );
        *req.method_mut() = Method::GET;
        let response = app.clone().oneshot(req).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS]
            .to_str()?
            .split(',')
            .any(|s| s.trim().eq_ignore_ascii_case("etag")));
        let tag = response.headers()[header::ETAG].clone();
        for (revision, expected) in [(0, StatusCode::OK), (1, StatusCode::PRECONDITION_FAILED)] {
            let mut req = request(
                &uri,
                json!({"baseRevision":revision,"values":{"browser":true}}),
                &session,
                "https://admin.aegaeon.test",
                true,
            );
            *req.method_mut() = Method::PUT;
            req.headers_mut().insert(header::IF_MATCH, tag.clone());
            assert_eq!(app.clone().oneshot(req).await?.status(), expected);
        }
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}
