use super::*;
use serde_json::{json, Value};
mod clients;
mod objects;
mod recipients;
mod targets;

#[tokio::test]
async fn organizations_session_worker_keeps_admission_after_caller_cancel() -> ManagementTestResult
{
    use crate::organizations::request_work::Admission;
    use crate::web::management::organizations::boundary::require_organization_management_session;
    let mgmt = test_management_state();
    let now = crate::web::now_epoch_secs()?;
    let sid = mgmt
        .sessions
        .try_create(Uuid::new_v4(), now)?
        .ok_or("session")?;
    let crate::web::management::state::ManagementSessionBackend::InMemory(memory) =
        &mgmt.sessions.backend
    else {
        return Err("expected memory fixture".into());
    };
    let memory = memory.clone();
    let (started, observe) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let guard = memory.write().unwrap();
        let _ = started.send(());
        let result = held.recv_timeout(std::time::Duration::from_secs(5));
        drop(guard);
        result
    });
    observe.await?;
    let pool = PgPoolOptions::new().connect_lazy("postgres://unused@localhost/unused")?;
    let state = test_app_state(pool.clone(), mgmt)?;
    let held: Vec<_> = (0..3)
        .map(|_| Admission::try_acquire())
        .collect::<Result<_, _>>()?;
    let lease = Admission::try_acquire()?;
    let mut headers = HeaderMap::new();
    headers.insert("cookie", format!("aegaeon_admin_session={sid}").parse()?);
    let (polled, started) = tokio::sync::oneshot::channel();
    let caller = tokio::spawn(async move {
        let lookup =
            require_organization_management_session(&state, &headers, &lease, "session-cancel");
        tokio::pin!(lookup);
        tokio::select! {
            biased;
            result = &mut lookup => result,
            () = tokio::task::yield_now() => {
                let _ = polled.send(());
                lookup.await
            }
        }
    });
    started.await?;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    let retained = Admission::try_acquire().is_err();
    // Release before asserting so a failing negative control leaves no worker.
    release.send(())?;
    blocker.join().map_err(|_| "blocking fixture panicked")??;
    assert!(
        retained,
        "caller cancellation released a live session worker's lease"
    );
    let returned = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Ok(lease) = Admission::try_acquire() {
                break lease;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    drop((returned, held));
    pool.close().await;
    Ok(())
}

fn mutation(
    uri: &str,
    method: Method,
    payload: Value,
    cookie: &str,
    key: &str,
    etag: Option<&str>,
) -> Request<Body> {
    let mut req = request(uri, payload, cookie, "https://admin.aegaeon.test", true);
    *req.method_mut() = method;
    req.headers_mut()
        .insert("idempotency-key", key.parse().unwrap());
    if let Some(etag) = etag {
        req.headers_mut().insert("if-match", etag.parse().unwrap());
    }
    req
}

async fn representation(
    response: Response,
    status: StatusCode,
) -> Result<(Value, String), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), status);
    assert!(response
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()?
        .contains("no-store"));
    let tag = response.headers().get("etag").unwrap().to_str()?.to_owned();
    let bytes = body::to_bytes(response.into_body(), 65_536).await?;
    Ok((serde_json::from_slice(&bytes)?, tag))
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_bootstrap_grants_preconditions_replay_and_revocation(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let mut mgmt = test_management_state();
        mgmt.cfg = Arc::new(super::super::super::ManagementConfig::try_from_env_with_database(&pool).await?);
        let sessions = mgmt.sessions.clone();
        let app = crate::web::build_router(test_app_state(pool.clone(), mgmt)?);
        let login = app.clone().oneshot(request("/api/v1/authentication/sessions", json!({"email":input().owner_email,"password":input().owner_password}), "", "https://admin.aegaeon.test", true)).await?;
        assert_eq!(login.status(), StatusCode::NO_CONTENT);
        let cookie = login.headers().get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()).find(|v| v.starts_with("aegaeon_admin_session=")).ok_or("session")?.split(';').next().ok_or("cookie")?.to_owned();
        let base = format!("/api/v1/teams/{}/environments/{}/organization-domains", initialized.team_id, initialized.environment_id);
        let bootstrap = format!("{base}/default");
        for (session, csrf, origin, status) in [
            ("", true, "https://admin.aegaeon.test", StatusCode::UNAUTHORIZED),
            (cookie.as_str(), false, "https://admin.aegaeon.test", StatusCode::FORBIDDEN),
            (cookie.as_str(), true, "https://untrusted.example", StatusCode::FORBIDDEN),
        ] {
            let mut req = request(&bootstrap, json!({"reason":"initialize"}), session, origin, csrf);
            req.headers_mut().insert("idempotency-key", "bootstrap".parse()?);
            let response = app.clone().oneshot(req).await?;
            assert_eq!(response.status(), status);
            assert!(response.headers().get("cache-control").unwrap().to_str()?.contains("no-store"));
        }
        let body = json!({"reason":"initialize"});
        let (created, tag) = representation(app.clone().oneshot(mutation(&bootstrap, Method::POST, body.clone(), &cookie, "bootstrap", None)).await?, StatusCode::OK).await?;
        assert_eq!(created["enabled"], false);
        assert_eq!(created["operator"]["capabilities"], json!(["configure"]));
        let (replay, replay_tag) = representation(app.clone().oneshot(mutation(&bootstrap, Method::POST, body, &cookie, "bootstrap", None)).await?, StatusCode::OK).await?;
        assert_eq!((created.clone(), tag), (replay, replay_tag));
        let domain = created["id"].as_str().ok_or("domain")?;
        assert!(Uuid::parse_str(domain).is_ok());
        let operators = format!("{base}/{domain}/operators");
        let target = Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.administrators(id,email,password_hash,kind,status) VALUES ($1,$2,'fixture-only','HUMAN','ACTIVE')")
            .bind(target).bind(format!("{target}@operator.example")).execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.team_memberships(team_id,administrator_id,role) VALUES ($1,$2,'READONLY')")
            .bind(initialized.team_id).bind(target).execute(&pool).await?;
        let payload = json!({"administratorId":target,"active":true,"capabilities":["reconcile"],"reason":"explicit grant"});
        let (grant, grant_tag) = representation(app.clone().oneshot(mutation(&operators, Method::POST, payload.clone(), &cookie, "create", None)).await?, StatusCode::OK).await?;
        // Configuration reads require configure; ordinary Team ownership and
        // a reconcile grant do not supply it. Cursors bind both scope dimensions.
        let read_request = |uri: &str, cookie: &str| Request::builder().uri(uri).header("cookie",cookie).body(Body::empty()).unwrap();
        let first_page = app.clone().oneshot(read_request(&format!("{operators}?pageSize=1"),&cookie)).await?;
        assert_eq!(first_page.status(),StatusCode::OK);
        assert!(first_page.headers().get("cache-control").unwrap().to_str()?.contains("no-store"));
        let first_page: Value = serde_json::from_slice(&body::to_bytes(first_page.into_body(),65536).await?)?;
        assert_eq!(first_page["operators"].as_array().ok_or("operators")?.len(),1);
        let cursor = first_page["pageInfo"]["nextPageToken"].as_str().ok_or("cursor")?;
        let second_page = app.clone().oneshot(read_request(&format!("{operators}?pageSize=1&pageToken={cursor}"),&cookie)).await?;
        assert_eq!(second_page.status(),StatusCode::OK);
        let second_page: Value = serde_json::from_slice(&body::to_bytes(second_page.into_body(),65536).await?)?;
        assert_eq!(second_page["operators"].as_array().ok_or("operators")?.len(),1);
        assert_ne!(first_page["operators"][0]["id"],second_page["operators"][0]["id"]);
        assert!(second_page["pageInfo"]["nextPageToken"].is_null());
        for query in ["pageSize=0","pageSize=101","pageSize=01","pageSize=1&pageSize=2","pageToken=invalid","unknown=1"] {
            let response = app.clone().oneshot(read_request(&format!("{operators}?{query}"),&cookie)).await?;
            assert_eq!(response.status(),StatusCode::BAD_REQUEST);
            let error: Value = serde_json::from_slice(&body::to_bytes(response.into_body(),65536).await?)?;
            assert_eq!(error["errorCode"],"invalid_request");
        }
        for request in [
            Request::builder().uri(&operators).header("cookie",&cookie).body(Body::from("{}"))?,
            read_request(&operators.replace(domain,"organization_00000000-0000-0000-0000-000000000001"),&cookie),
        ] {
            let response = app.clone().oneshot(request).await?;
            assert_eq!(response.status(),StatusCode::BAD_REQUEST);
            assert!(response.headers()["cache-control"].to_str()?.contains("no-store"));
            let error: Value = serde_json::from_slice(&body::to_bytes(response.into_body(),65536).await?)?;
            assert_eq!(error["errorCode"],"invalid_request");
        }
        let target_session = sessions.try_create(target,crate::web::now_epoch_secs()?)?.ok_or("target session")?;
        assert_eq!(app.clone().oneshot(read_request(&operators,&format!("aegaeon_admin_session={target_session}"))).await?.status(),StatusCode::FORBIDDEN);
        let second_domain = Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.authorization_domains(id,environment_id,name) VALUES ($1,$2,'second')").bind(second_domain).bind(initialized.environment_id).execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.organization_operator_grants(id,environment_id,domain_id,administrator_id,active,capabilities) VALUES ($1,$2,$3,$4,true,'[\"configure\"]')")
            .bind(Uuid::new_v4()).bind(initialized.environment_id).bind(second_domain).bind(initialized.administrator_id).execute(&pool).await?;
        let other_scope = format!("{base}/{second_domain}/operators?pageToken={cursor}");
        assert_eq!(app.clone().oneshot(read_request(&other_scope,&cookie)).await?.status(),StatusCode::BAD_REQUEST);
        let grant_id = grant["id"].as_str().ok_or("id")?;
        assert!(Uuid::parse_str(grant_id).is_ok());
        let path = format!("{operators}/{grant_id}");
        let update = json!({"active":true,"capabilities":["export"],"reason":"replace capability"});
        for (etag, expected) in [(None,StatusCode::PRECONDITION_REQUIRED), (Some("*"),StatusCode::PRECONDITION_REQUIRED), (Some("\"11111111-1111-4111-8111-111111111111.1\""),StatusCode::PRECONDITION_FAILED)] {
            let response = app.clone().oneshot(mutation(&path, Method::PATCH, update.clone(), &cookie, "update", etag)).await?;
            assert_eq!(response.status(), expected);
        }
        let (updated, updated_tag) = representation(app.clone().oneshot(mutation(&path, Method::PATCH, update.clone(), &cookie, "update", Some(&grant_tag))).await?,StatusCode::OK).await?;
        assert_eq!(updated["revision"], 2);
        assert_eq!(updated["capabilities"], json!(["export"]));
        let (retry, _) = representation(app.clone().oneshot(mutation(&path, Method::PATCH, update.clone(), &cookie, "update", Some(&grant_tag))).await?,StatusCode::OK).await?;
        assert_eq!(retry,updated);
        assert_eq!(app.clone().oneshot(mutation(&path, Method::PATCH, update, &cookie, "stale", Some(&grant_tag))).await?.status(),StatusCode::PRECONDITION_FAILED);
        let other = operators.replace(domain, &Uuid::new_v4().to_string());
        assert_eq!(app.clone().oneshot(mutation(&other,Method::POST,payload.clone(),&cookie,"create",None)).await?.status(),StatusCode::FORBIDDEN);
        // All ordinary permits are held. Only the revoke-only route can proceed.
        // Earlier refusals may still own a connection while rollback drains.
        // Wait for observed cleanup completion, not a guessed sleep interval.
        let held = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(held) = (0..4).map(|_| crate::organizations::request_work::Admission::try_acquire()).collect::<Result<Vec<_>,_>>() {
                    break held;
                }
                tokio::task::yield_now().await;
            }
        }).await.map_err(|_| "ordinary request leases did not finish cleanup")?;
        assert_eq!(app.clone().oneshot(mutation(&operators, Method::POST, payload, &cookie, "blocked",None)).await?.status(),StatusCode::SERVICE_UNAVAILABLE);
        let (revoked,_) = representation(app.clone().oneshot(mutation(&format!("{path}/revoke"),Method::POST,json!({"reason":"revoke"}),&cookie,"revoke",Some(&updated_tag))).await?,StatusCode::OK).await?;
        assert_eq!(revoked["active"],false);
        assert_eq!(revoked["capabilities"],json!(["export"]));
        drop(held);
        let sid = cookie.strip_prefix("aegaeon_admin_session=").ok_or("sid")?;
        assert!(sessions.try_delete(sid)?);
        assert_eq!(app.oneshot(mutation(&bootstrap,Method::POST,json!({"reason":"initialize"}),&cookie,"bootstrap",None)).await?.status(),StatusCode::UNAUTHORIZED);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_refuses_ambiguous_inputs_api_keys_and_database_loss(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let mut mgmt = test_management_state();
        mgmt.cfg = Arc::new(
            super::super::super::ManagementConfig::try_from_env_with_database(&pool).await?,
        );
        let now = crate::web::now_epoch_secs()?;
        let sid = mgmt
            .sessions
            .try_create(initialized.administrator_id, now)?
            .ok_or("session")?;
        let cookie = format!("aegaeon_admin_session={sid}");
        let app = crate::web::build_router(test_app_state(pool.clone(), mgmt)?);
        let path = format!(
            "/api/v1/teams/{}/environments/{}/organization-domains/default",
            initialized.team_id, initialized.environment_id
        );
        for (body, expected) in [
            (
                br#"{"reason":"one","reason":"two"}"#.to_vec(),
                StatusCode::BAD_REQUEST,
            ),
            (
                br#"{"reason":"init","actor_id":"11111111-1111-4111-8111-111111111111"}"#.to_vec(),
                StatusCode::BAD_REQUEST,
            ),
            (vec![0xff], StatusCode::BAD_REQUEST),
            (vec![b' '; 65_537], StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let mut req = mutation(
                &path,
                Method::POST,
                json!({"reason":"initialize"}),
                &cookie,
                "bounded",
                None,
            );
            *req.body_mut() = Body::from(body);
            let response = app.clone().oneshot(req).await?;
            assert_eq!(response.status(), expected);
            assert!(response
                .headers()
                .get("cache-control")
                .unwrap()
                .to_str()?
                .contains("no-store"));
        }
        let mut ambiguous = mutation(
            &path,
            Method::POST,
            json!({"reason":"initialize"}),
            &cookie,
            "one",
            None,
        );
        ambiguous
            .headers_mut()
            .append("idempotency-key", "two".parse()?);
        assert_eq!(
            app.clone().oneshot(ambiguous).await?.status(),
            StatusCode::BAD_REQUEST
        );
        let mut api_key = mutation(
            &path,
            Method::POST,
            json!({"reason":"initialize"}),
            "",
            "key",
            None,
        );
        api_key.headers_mut().remove("cookie");
        api_key
            .headers_mut()
            .insert("authorization", "Bearer aeg_fixture_api_key".parse()?);
        assert_eq!(
            app.clone().oneshot(api_key).await?.status(),
            StatusCode::FORBIDDEN
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.authorization_domains WHERE environment_id=$1",
        )
        .bind(initialized.environment_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(count, 0);
        let request = || {
            mutation(
                &path,
                Method::POST,
                json!({"reason":"initialize"}),
                &cookie,
                "success",
                None,
            )
        };
        representation(app.clone().oneshot(request()).await?, StatusCode::OK).await?;
        pool.close().await;
        let response = app.oneshot(request()).await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()?
            .contains("no-store"));
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}
