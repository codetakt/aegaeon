//! Actual management PATCH followed by stale owner PUT, with observed DB waits.
use super::*;
use crate::dcr_persistence::{self, DcrClientSecretChange, DcrDatabaseError};
use serde_json::{json, Value};
use std::time::Duration;

async fn saved(
    pool: &PgPool,
    environment: Uuid,
) -> crate::web::test_support::TestResult<Vec<String>> {
    let mut rows = Vec::new();
    for table in [
        "clients",
        "client_secrets",
        "dynamic_client_registrations",
        "audit_events",
    ] {
        rows.push(sqlx::query_scalar(&format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM aegaeon.{table} t WHERE environment_id=$1"))
            .bind(environment).fetch_one(pool).await?);
    }
    Ok(rows)
}

async fn waiter(
    pool: &PgPool,
    blocker: i32,
    query: &str,
) -> crate::web::test_support::TestResult<i32> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE $2 LIMIT 1")
                .bind(blocker).bind(format!("%{query}%")).fetch_optional(pool).await?;
            if let Some(pid) = pid { return Ok::<_, sqlx::Error>(pid); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??)
}

fn owner_request(method: Method, name: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(format!("/register/{name}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            json!({"client_id":name,"pkce_required":true}).to_string(),
        ))
        .unwrap()
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; real management and owner HTTP writers with observed locks"]
async fn pg_registration_currentness_preserves_management_metadata_and_profile(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let init = initialize_management(&pool, &input()).await?;
        let env = crate::web::test_support::TestEnvironment {
            team_id: init.team_id, tenant_id: init.tenant_id, environment_id: init.environment_id,
            issuer_url: format!("https://{}", init.issuer_host), issuer_host: init.issuer_host.clone(),
        };
        let mut profiles = Vec::new();
        for (label, default) in [("original", true), ("replacement", false)] {
            let id: Uuid = sqlx::query_scalar("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,allowed_grant_types,token_endpoint_auth_methods_allowed) VALUES($1,$2,$3,'DOWNSTREAM',$4,ARRAY['authorization_code'],ARRAY['client_secret_basic']) RETURNING id")
                .bind(init.environment_id).bind(init.configuration_version_id).bind(label).bind(default).fetch_one(&pool).await?;
            profiles.push(id);
        }
        let mut client = crate::web::test_support::sample_registered_client("managed-registration");
        client.token_endpoint_auth_method = "client_secret_basic".into();
        client.client_secret = Some("currentness-issued-secret".into());
        client.allowed_grant_types = vec!["authorization_code".into()];
        client.allowed_scopes = vec!["openid".into()];
        let token = "currentness-owner-registration-token";
        dcr_persistence::create_dynamic_registration(&pool, &init.issuer_host, &client, &["code".into()], token, "currentness-create").await?;
        let mut state = crate::web::test_support::test_app_state(pool.clone(), &env).await?;
        crate::web::test_support::update_test_policy(&mut state, |policy| {
            policy.dcr_enabled = true;
            policy.dcr_everparse_runtime_enabled = true;
        }).await?;
        let registry = state.clients.clone();
        let app = crate::web::build_router(state);
        let (management, session) = super::target_scope_boundary::reloaded_management_session(&pool, &env).await?;
        // Two independent discriminators: inherited redirects + explicit profile,
        // then profile assignment alone with unchanged owner metadata.
        for (index, profile) in [profiles[1], profiles[0]].into_iter().enumerate() {
            let prepared = dcr_persistence::load_dynamic_registration_by_token(&pool, &init.issuer_host, &client.client_id, token).await?.ok_or("preloaded owner")?;
            // Admit a read first so any prior management projection change is
            // synchronized before measuring this request's no-write behavior.
            let read = app.clone().oneshot(owner_request(Method::GET, &client.client_id, token)).await?;
            assert_eq!(read.status(), StatusCode::OK);
            let before = saved(&pool, init.environment_id).await?;
            let runtime = registry.try_runtime_snapshot_fingerprint()?;
            assert!(runtime.is_some());
            let mut blocker = pool.begin().await?;
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await?;
            // Deliberate test barrier: management owns environment, then waits
            // for this client row; owner authenticates old data and waits behind it.
            sqlx::query("SELECT id FROM aegaeon.clients WHERE id=$1 FOR UPDATE")
                .bind(prepared.database_client_id).execute(&mut *blocker).await?;
            let mut payload = json!({"baseConfigurationVersionId":init.configuration_version_id,"oauthProfileId":profile});
            if index == 0 { payload["redirectUris"] = json!(["https://client.example/managed"]); }
            let uri = format!("/api/v1/teams/{}/environments/{}/clients/{}",init.team_id,init.environment_id,prepared.database_client_id);
            let mut patch = request(&uri, payload, &session, "https://admin.aegaeon.test", true);
            *patch.method_mut() = Method::PATCH;
            let managed_app = management.clone();
            let mut managed = tokio::spawn(async move { managed_app.oneshot(patch).await });
            let observed = waiter(&pool, pid, "FOR UPDATE OF c").await;
            let management_pid = match observed {
                Ok(pid) => pid,
                Err(error) => { managed.abort(); let _ = managed.await; blocker.rollback().await?; return Err(error); }
            };
            let owner_app = app.clone();
            let req = owner_request(Method::PUT, &client.client_id, token);
            let mut owner = tokio::spawn(async move { owner_app.oneshot(req).await });
            if let Err(error) = waiter(&pool, management_pid, "SELECT id FROM aegaeon.environments WHERE id = $1 FOR UPDATE").await {
                owner.abort(); managed.abort(); let _ = owner.await; let _ = managed.await;
                blocker.rollback().await?; return Err(error);
            }
            blocker.commit().await?;
            let responses = tokio::time::timeout(Duration::from_secs(10), async {
                Ok::<_, Box<dyn std::error::Error>>(((&mut managed).await??, (&mut owner).await??))
            }).await;
            let (managed_response, response) = match responses {
                Ok(result) => result?,
                Err(error) => { owner.abort(); managed.abort(); let _ = owner.await; let _ = managed.await; return Err(error.into()); }
            };
            let status = managed_response.status();
            let value: Value = serde_json::from_slice(&body::to_bytes(managed_response.into_body(), 65536).await?)?;
            assert_eq!(status, StatusCode::OK, "{value}");
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let error: Value = serde_json::from_slice(&body::to_bytes(response.into_body(), 65536).await?)?;
            for private in [token, "currentness-issued-secret", &prepared.registration_access_token_hash, "preparation_snapshot"] {
                assert!(!error.to_string().contains(private));
            }
            let after = saved(&pool, init.environment_id).await?;
            assert_eq!(before[1], after[1], "credentials unchanged");
            assert_eq!(before[2], after[2], "owner RAT and registration unchanged");
            let audit: Value = serde_json::from_str(&after[3])?;
            let old_audit: Value = serde_json::from_str(&before[3])?;
            let mut added_types: Vec<&str> = audit.as_array().unwrap().iter()
                .filter(|event| !old_audit.as_array().unwrap().contains(event))
                .map(|event| event["event_type"].as_str().expect("audit event type")).collect();
            added_types.sort_unstable();
            let mut expected = vec!["management.client.updated.v1", "management.oauthProfile.assigned.v1"];
            if index == 1 { expected.push("management.oauthProfile.unassigned.v1"); }
            expected.sort_unstable();
            assert_eq!(added_types, expected, "only management update and profile audit");
            assert!(!after[3].contains("currentness-issued-secret"));
            assert!(!after[3].contains("preparation_snapshot"));
            assert_eq!(runtime, registry.try_runtime_snapshot_fingerprint()?, "refused owner does not synchronize its runtime");
            let (redirects, actual_profile): (Vec<String>, Option<Uuid>) = sqlx::query_as("SELECT redirect_uris,oauth_profile_id FROM aegaeon.clients WHERE id=$1")
                .bind(prepared.database_client_id).fetch_one(&pool).await?;
            assert_eq!(redirects, ["https://client.example/managed"]);
            assert_eq!(actual_profile, Some(profile));
            // Repeat from the exact pre-management load: every persisted byte,
            // including management audit, must survive the refusal unchanged.
            let error = dcr_persistence::update_dynamic_registration(&pool, &prepared, &prepared.client, &prepared.response_types,
                "stale-candidate-token", DcrClientSecretChange::Preserve, Some("wrong-secret"), "stale-owner").await.expect_err("management drift");
            assert!(matches!(error, DcrDatabaseError::ConcurrentModification));
            assert_eq!(after, saved(&pool, init.environment_id).await?);
        }
        let response = app.oneshot(owner_request(Method::PUT, &client.client_id, "invalid-owner-token")).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
