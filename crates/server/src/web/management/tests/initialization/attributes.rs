use super::*;
use crate::attribute_mapping::{
    load_attribute_sources, replace_local_attributes, AttributeStoreError,
};
use serde_json::{json, Value};

mod boundaries;
mod review;

async fn create_user(pool: &PgPool, environment: Uuid) -> anyhow::Result<Uuid> {
    Ok(sqlx::query_scalar("INSERT INTO aegaeon.end_users (environment_id,subject,status) VALUES ($1,$2,'ACTIVE') RETURNING id")
        .bind(environment).bind(format!("attribute-user-{}", Uuid::new_v4())).fetch_one(pool).await?)
}

async fn authenticated_app(
    pool: &PgPool,
) -> Result<(axum::Router, String), Box<dyn std::error::Error>> {
    let mut management = test_management_state();
    management.cfg = std::sync::Arc::new(
        super::super::super::ManagementConfig::try_from_env_with_database(pool).await?,
    );
    let app = crate::web::build_router(test_app_state(pool.clone(), management)?);
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
    let session = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("aegaeon_admin_session="))
        .and_then(|value| value.split(';').next())
        .ok_or("missing session cookie")?
        .to_string();
    Ok((app, session))
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_management_preserves_versions_and_enforces_browser_authority(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let mut mgmt = test_management_state();
        mgmt.cfg = std::sync::Arc::new(super::super::super::ManagementConfig::try_from_env_with_database(&pool).await?);
        let app = crate::web::build_router(test_app_state(pool.clone(), mgmt)?);
        let login = app.clone().oneshot(request("/api/v1/authentication/sessions", json!({"email":input().owner_email,"password":input().owner_password}), "", "https://admin.aegaeon.test", true)).await?;
        assert_eq!(login.status(), StatusCode::NO_CONTENT);
        let session = login.headers().get_all("set-cookie").iter().filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("aegaeon_admin_session=")).ok_or_else(|| anyhow::anyhow!("missing session cookie"))?.split(';').next().ok_or_else(|| anyhow::anyhow!("empty session"))?.to_string();
        let uri = format!("/api/v1/teams/{}/environments/{}/users/{user}/attributes", initialized.team_id, initialized.environment_id);
        let payload = json!({"baseRevision":0,"values":{"department":"NeverLogAttributeValue","nullable":null,"nested":{"roles":["reader"]}}});
        for (cookie, origin, csrf, expected) in [
            ("", "https://admin.aegaeon.test", true, StatusCode::UNAUTHORIZED),
            (session.as_str(), "https://untrusted.example", true, StatusCode::FORBIDDEN),
            (session.as_str(), "https://admin.aegaeon.test", false, StatusCode::FORBIDDEN),
        ] {
            let mut req = request(&uri, payload.clone(), cookie, origin, csrf); *req.method_mut() = Method::PUT;
            let response = app.clone().oneshot(req).await?;
            assert_eq!(response.status(), expected);
            assert!(load_attribute_sources(&pool, initialized.environment_id, user).await?.is_empty());
        }
        let mut req = request(&uri, payload.clone(), &session, "https://admin.aegaeon.test", true); *req.method_mut() = Method::PUT;
        let response = app.clone().oneshot(req).await?;
        let status = response.status(); let bytes = body::to_bytes(response.into_body(), 65536).await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&bytes));
        let returned: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(returned["source"]["revision"], 1);
        assert_eq!(returned["source"]["values"], payload["values"]);
        assert_eq!(returned["source"]["provenance"]["kind"], "local");
        let mut req = request(&uri, payload, &session, "https://admin.aegaeon.test", true); *req.method_mut() = Method::PUT;
        assert_eq!(app.clone().oneshot(req).await?.status(), StatusCode::CONFLICT);
        let mut forged = request(&uri, json!({"baseRevision":1,"values":{},"source":"connection:forged"}), &session, "https://admin.aegaeon.test", true); *forged.method_mut() = Method::PUT;
        assert_eq!(app.clone().oneshot(forged).await?.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let mut req = request(&uri, Value::Null, &session, "https://admin.aegaeon.test", true); *req.method_mut() = Method::GET;
        let response = app.clone().oneshot(req).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let view: Value = serde_json::from_slice(&body::to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(view["sources"][0]["values"]["nullable"], Value::Null);
        let mut req = request(&uri, json!({"baseRevision":1,"values":{}}), &session, "https://admin.aegaeon.test", true); *req.method_mut() = Method::PUT;
        assert_eq!(app.oneshot(req).await?.status(), StatusCode::OK);
        let records = load_attribute_sources(&pool, initialized.environment_id, user).await?;
        assert_eq!(records[0].revision, 2);
        assert_eq!(records[0].values, json!({}));
        let audit: String = sqlx::query_scalar("SELECT jsonb_agg(data)::text FROM aegaeon.audit_events").fetch_one(&pool).await?;
        assert!(!audit.contains("NeverLogAttributeValue"));
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_source_concurrent_create_has_one_winner_and_keeps_owners_separate(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let other = create_user(&pool, initialized.environment_id).await?;
        let actor = Uuid::new_v4();
        let write = |value: &'static str| {
            let pool = pool.clone();
            async move {
                let mut tx = pool.begin().await?;
                let result = replace_local_attributes(
                    &mut tx,
                    initialized.environment_id,
                    user,
                    0,
                    &json!({"value":value}),
                    actor,
                )
                .await;
                match result {
                    Ok(record) => {
                        tx.commit().await?;
                        Ok(record)
                    }
                    Err(error) => {
                        tx.rollback().await?;
                        Err(error)
                    }
                }
            }
        };
        let (a, b) = tokio::join!(write("first"), write("second"));
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert!(matches!(
            (&a, &b),
            (
                Err(AttributeStoreError::RevisionMismatch { current: 1 }),
                Ok(_)
            ) | (
                Ok(_),
                Err(AttributeStoreError::RevisionMismatch { current: 1 })
            )
        ));
        assert!(
            load_attribute_sources(&pool, initialized.environment_id, other)
                .await?
                .is_empty()
        );
        assert!(load_attribute_sources(&pool, Uuid::new_v4(), user)
            .await?
            .is_empty());
        let mut tx = pool.begin().await?;
        assert!(matches!(
            replace_local_attributes(&mut tx, Uuid::new_v4(), user, 1, &json!({}), actor).await,
            Err(AttributeStoreError::OwnerNotFound)
        ));
        tx.rollback().await?;
        let sources = load_attribute_sources(&pool, initialized.environment_id, user).await?;
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].revision, 1);
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_migration_does_not_invent_legacy_provenance() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        // Only the test administrator reconstructs this additive migration's
        // predecessor. The application keeps its restricted runtime login.
        let admin = PgPoolOptions::new().max_connections(1)
            .connect_with(control.connect_options().as_ref().clone().database(&name)).await?;
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        sqlx::query("INSERT INTO aegaeon.end_user_profiles (end_user_id,custom_claims) VALUES ($1,$2)").bind(user).bind(json!({"legacy":"unattributed"})).execute(&pool).await?;
        let before: Value = sqlx::query_scalar("SELECT to_jsonb(p) FROM aegaeon.end_user_profiles p WHERE end_user_id=$1").bind(user).fetch_one(&pool).await?;
        sqlx::raw_sql("DROP TABLE aegaeon.user_attribute_sources; ALTER TABLE aegaeon.end_users DROP CONSTRAINT end_users_environment_id_id_unique; ALTER TABLE aegaeon.connections DROP CONSTRAINT connections_environment_id_id_unique;").execute(&admin).await?;
        sqlx::raw_sql(include_str!("../../../../../../../db/migrations/20261101090000_user_attribute_sources.sql")).execute(&admin).await?;
        // A newly created table does not inherit the earlier fixture's explicit
        // runtime grants. Confirm fail-closed behavior, then apply only the
        // management operations documented for this additive table.
        assert!(matches!(load_attribute_sources(&pool, initialized.environment_id, user).await,
            Err(AttributeStoreError::Database(sqlx::Error::Database(error))) if error.code().as_deref() == Some("42501")));
        let runtime: String = sqlx::query_scalar("SELECT quote_ident(current_user)")
            .fetch_one(&pool).await?;
        sqlx::raw_sql(&format!("GRANT SELECT,INSERT,UPDATE ON aegaeon.user_attribute_sources TO {runtime}"))
            .execute(&admin).await?;
        admin.close().await;
        let after: Value = sqlx::query_scalar("SELECT to_jsonb(p) FROM aegaeon.end_user_profiles p WHERE end_user_id=$1").bind(user).fetch_one(&pool).await?;
        assert_eq!(before, after);
        assert!(load_attribute_sources(&pool, initialized.environment_id, user).await?.is_empty());
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_catalog_rejects_pre_attribute_checker() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let admin = PgPoolOptions::new().max_connections(1)
            .connect_with(control.connect_options().as_ref().clone().database(&name)).await?;
        let query = "SELECT * FROM aegaeon.validate_subject_ownership_namespace_v1($1)";
        sqlx::query(query).bind(initialized.environment_id).fetch_all(&pool).await?;
        // Actual old checkers retain their owner/ACL. The original refuses the
        // attribute ownership key; the attribute successor refuses the LTI ledger.
        for (source, refusal) in [
            (include_str!("../../../../../../../db/migrations/20261029052000_subject_prerequisite_catalog.sql"), Some("subject physical schema or trigger definition mismatch")),
            (include_str!("../../../../../../../db/migrations/20261101090000_user_attribute_sources.sql"), Some("subject physical schema or trigger definition mismatch")),
            (include_str!("../../../../../../../db/migrations/20261102101000_lti_subject_inventory.sql"), None),
        ] {
            let marker = "CREATE OR REPLACE FUNCTION aegaeon.subject_history_preflight(";
            let definition = source.split_once(marker).ok_or("missing preflight definition")?.1
                .split_once("$function$;").ok_or("missing preflight terminator")?.0;
            sqlx::raw_sql(&format!("{marker}{definition}$function$;")).execute(&admin).await?;
            let observed = sqlx::query(query).bind(initialized.environment_id).fetch_all(&pool).await;
            if let Some(refusal) = refusal {
                assert!(matches!(observed, Err(sqlx::Error::Database(error))
                    if error.message() == refusal));
            } else {
                observed?;
            }
        }
        admin.close().await;
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_management_rechecks_role_and_deleted_owner() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let (app, session) = authenticated_app(&pool).await?;
        let uri = format!("/api/v1/teams/{}/environments/{}/users/{user}/attributes", initialized.team_id, initialized.environment_id);
        let payload = json!({"baseRevision":0,"values":{"department":"Engineering"}});
        sqlx::query("UPDATE aegaeon.team_memberships SET role='READONLY' WHERE team_id=$1 AND administrator_id=$2")
            .bind(initialized.team_id).bind(initialized.administrator_id).execute(&pool).await?;
        for method in [Method::GET, Method::PUT] {
            let mut req = request(&uri, payload.clone(), &session, "https://admin.aegaeon.test", true);
            *req.method_mut() = method;
            assert_eq!(app.clone().oneshot(req).await?.status(), StatusCode::FORBIDDEN);
        }
        assert!(load_attribute_sources(&pool, initialized.environment_id, user).await?.is_empty());
        sqlx::query("UPDATE aegaeon.team_memberships SET role='ADMINISTRATOR' WHERE team_id=$1 AND administrator_id=$2")
            .bind(initialized.team_id).bind(initialized.administrator_id).execute(&pool).await?;
        let mut req = request(&uri, payload.clone(), &session, "https://admin.aegaeon.test", true);
        *req.method_mut() = Method::PUT;
        assert_eq!(app.clone().oneshot(req).await?.status(), StatusCode::OK);
        sqlx::query("UPDATE aegaeon.end_users SET status='DELETED' WHERE id=$1").bind(user).execute(&pool).await?;
        for method in [Method::GET, Method::PUT] {
            let mut req = request(&uri, json!({"baseRevision":1,"values":{}}), &session, "https://admin.aegaeon.test", true);
            *req.method_mut() = method;
            assert_eq!(app.clone().oneshot(req).await?.status(), StatusCode::NOT_FOUND);
        }
        let revision: i64 = sqlx::query_scalar("SELECT revision FROM aegaeon.user_attribute_sources WHERE end_user_id=$1")
            .bind(user).fetch_one(&pool).await?;
        assert_eq!(revision, 1);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_management_rolls_back_values_when_audit_fails() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let (app, session) = authenticated_app(&pool).await?;
        let uri = format!("/api/v1/teams/{}/environments/{}/users/{user}/attributes", initialized.team_id, initialized.environment_id);
        let payload = json!({"baseRevision":0,"values":{"department":"Engineering"}});
        let admin = PgPoolOptions::new().max_connections(1)
            .connect_with(control.connect_options().as_ref().clone().database(&name)).await?;
        sqlx::raw_sql("ALTER TABLE aegaeon.audit_events ADD CONSTRAINT reject_attribute_audit CHECK (event_type <> 'management.user.attributes.replaced.v1')")
            .execute(&admin).await?;
        let mut req = request(&uri, payload.clone(), &session, "https://admin.aegaeon.test", true);
        *req.method_mut() = Method::PUT;
        assert_eq!(app.clone().oneshot(req).await?.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(load_attribute_sources(&pool, initialized.environment_id, user).await?.is_empty());
        sqlx::raw_sql("ALTER TABLE aegaeon.audit_events DROP CONSTRAINT reject_attribute_audit").execute(&admin).await?;
        admin.close().await;
        let mut req = request(&uri, payload, &session, "https://admin.aegaeon.test", true);
        *req.method_mut() = Method::PUT;
        assert_eq!(app.oneshot(req).await?.status(), StatusCode::OK);
        let sources = load_attribute_sources(&pool, initialized.environment_id, user).await?;
        assert_eq!(sources[0].revision, 1);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE event_type='management.user.attributes.replaced.v1'")
            .fetch_one(&pool).await?;
        assert_eq!(count, 1);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
