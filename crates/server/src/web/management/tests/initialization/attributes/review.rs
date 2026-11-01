use super::*;
use axum::http::header::{ETAG, IF_MATCH};
use std::time::Duration;

async fn get(app: &axum::Router, uri: &str, session: &str) -> axum::response::Response {
    let mut req = request(
        uri,
        Value::Null,
        session,
        "https://admin.aegaeon.test",
        true,
    );
    *req.method_mut() = Method::GET;
    app.clone().oneshot(req).await.unwrap()
}

async fn put(
    app: &axum::Router,
    uri: &str,
    session: &str,
    revision: i64,
    values: Value,
    etag: Option<&str>,
) -> axum::response::Response {
    let mut req = request(
        uri,
        json!({"baseRevision":revision,"values":values}),
        session,
        "https://admin.aegaeon.test",
        true,
    );
    *req.method_mut() = Method::PUT;
    if let Some(etag) = etag {
        req.headers_mut().insert(IF_MATCH, etag.parse().unwrap());
    }
    app.clone().oneshot(req).await.unwrap()
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_write_rejects_expanded_database_size() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let (app, session) = authenticated_app(&pool).await?;
        let uri = format!(
            "/api/v1/teams/{}/environments/{}/users/{user}/attributes",
            initialized.team_id, initialized.environment_id
        );
        let expanded = json!({"numbers":vec![vec![1e-300; 1024]; 4]});
        assert!(serde_json::to_vec(&expanded)?.len() < aegaeon_attribute_mapping::MAX_INPUT_BYTES);
        let database_size: i32 = sqlx::query_scalar("SELECT octet_length($1::jsonb::text)")
            .bind(&expanded)
            .fetch_one(&pool)
            .await?;
        assert!(database_size > 1_048_576);
        assert_eq!(
            put(&app, &uri, &session, 0, expanded, None).await.status(),
            StatusCode::BAD_REQUEST
        );
        assert!(
            load_attribute_sources(&pool, initialized.environment_id, user)
                .await?
                .is_empty()
        );
        assert_eq!(
            put(&app, &uri, &session, 0, json!({"numbers":[1e-300]}), None)
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(get(&app, &uri, &session).await.status(), StatusCode::OK);
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_write_rejects_nested_nul_before_database() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let (app, session) = authenticated_app(&pool).await?;
        let uri = format!(
            "/api/v1/teams/{}/environments/{}/users/{user}/attributes",
            initialized.team_id, initialized.environment_id
        );
        for invalid in [
            json!({"note":"\u{0}"}),
            json!({"nested":[{"bad\u{0}key":"value"}]}),
            json!({"nested":[["\u{0}"]]}),
        ] {
            assert_eq!(
                put(&app, &uri, &session, 0, invalid, None).await.status(),
                StatusCode::BAD_REQUEST
            );
            assert!(
                load_attribute_sources(&pool, initialized.environment_id, user)
                    .await?
                    .is_empty()
            );
        }
        assert_eq!(
            put(
                &app,
                &uri,
                &session,
                0,
                json!({"note":"日本語\ntext"}),
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(get(&app, &uri, &session).await.status(), StatusCode::OK);
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_management_if_match_is_atomic_with_revision() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let (app, session) = authenticated_app(&pool).await?;
        let uri = format!(
            "/api/v1/teams/{}/environments/{}/users/{user}/attributes",
            initialized.team_id, initialized.environment_id
        );
        let initial = get(&app, &uri, &session).await;
        assert_eq!(initial.status(), StatusCode::OK);
        let tag = initial.headers()[ETAG].to_str()?.to_string();
        assert_eq!(
            put(&app, &uri, &session, 0, json!({"value":1}), Some(&tag))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            put(&app, &uri, &session, 1, json!({"value":2}), Some(&tag))
                .await
                .status(),
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(
            load_attribute_sources(&pool, initialized.environment_id, user).await?[0].revision,
            1
        );
        let current = get(&app, &uri, &session).await;
        let tag = current.headers()[ETAG].to_str()?.to_string();
        assert_eq!(
            put(
                &app,
                &uri,
                &session,
                1,
                json!({}),
                Some(&format!("W/{tag}"))
            )
            .await
            .status(),
            StatusCode::PRECONDITION_FAILED
        );
        let (a, b) = tokio::join!(
            put(&app, &uri, &session, 1, json!({"value":"a"}), Some(&tag)),
            put(&app, &uri, &session, 1, json!({"value":"b"}), Some(&tag))
        );
        let mut statuses = [a.status().as_u16(), b.status().as_u16()];
        statuses.sort();
        assert_eq!(statuses, [200, 412]);
        assert_eq!(
            put(&app, &uri, &session, 2, json!({}), Some("*"))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            load_attribute_sources(&pool, initialized.environment_id, user).await?[0].revision,
            3
        );
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_reads_share_lifecycle_locks() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let other = create_user(&pool, initialized.environment_id).await?;
        let (app, session) = authenticated_app(&pool).await?;
        let mut shared = pool.begin().await?;
        sqlx::query("SELECT m.team_id FROM aegaeon.team_memberships m JOIN aegaeon.teams t ON t.id=m.team_id JOIN aegaeon.administrators a ON a.id=m.administrator_id WHERE m.team_id=$1 FOR SHARE OF m,t,a").bind(initialized.team_id).fetch_all(&mut *shared).await?;
        sqlx::query("SELECT u.id FROM aegaeon.end_users u JOIN aegaeon.environments e ON e.id=u.environment_id JOIN aegaeon.tenants t ON t.id=e.tenant_id WHERE u.id=$1 FOR SHARE OF u,e,t").bind(user).fetch_all(&mut *shared).await?;
        for target in [user,other] {
            let uri = format!("/api/v1/teams/{}/environments/{}/users/{target}/attributes", initialized.team_id, initialized.environment_id);
            let response = tokio::time::timeout(Duration::from_secs(5), get(&app,&uri,&session)).await?;
            assert_eq!(response.status(),StatusCode::OK);
        }
        shared.rollback().await?;
        // Pause an actual GET at its source-table read, after it has taken the
        // shared authority/owner locks. Every relevant writer must still wait.
        let admin = PgPoolOptions::new().max_connections(1)
            .connect_with(control.connect_options().as_ref().clone().database(&name)).await?;
        let mut barrier = admin.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.user_attribute_sources IN ACCESS EXCLUSIVE MODE").execute(&mut *barrier).await?;
        let uri = format!("/api/v1/teams/{}/environments/{}/users/{user}/attributes", initialized.team_id, initialized.environment_id);
        let pending = tokio::spawn(async move { get(&app, &uri, &session).await });
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.relation='aegaeon.user_attribute_sources'::regclass AND NOT l.granted AND a.query LIKE '%a.source_namespace%')").fetch_one(&pool).await?;
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<(),sqlx::Error>(())
        }).await??;
        for (query, id) in [
            ("UPDATE aegaeon.team_memberships SET role=role WHERE team_id=$1", initialized.team_id),
            ("UPDATE aegaeon.administrators SET status=status WHERE id=$1", initialized.administrator_id),
            ("UPDATE aegaeon.teams SET status=status WHERE id=$1", initialized.team_id),
            ("UPDATE aegaeon.end_users SET status=status WHERE id=$1", user),
            ("UPDATE aegaeon.environments SET status=status WHERE id=$1", initialized.environment_id),
            ("UPDATE aegaeon.tenants SET status=status WHERE id=$1", initialized.tenant_id),
        ] {
            let mut writer = pool.begin().await?;
            sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *writer).await?;
            let result = sqlx::query(query).bind(id).execute(&mut *writer).await;
            assert!(matches!(result,Err(sqlx::Error::Database(error)) if error.code().as_deref()==Some("55P03")));
            writer.rollback().await?;
        }
        barrier.rollback().await?;
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), pending).await??.status(),StatusCode::OK);
        admin.close().await;
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_physical_deletion_preserves_permanent_subject_ownership(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let (app, session) = authenticated_app(&pool).await?;
        let admin = PgPoolOptions::new().max_connections(1)
            .connect_with(control.connect_options().as_ref().clone().database(&name)).await?;
        let key: String = sqlx::query_scalar("SELECT quote_ident(conname) FROM pg_constraint WHERE conrelid='aegaeon.user_attribute_sources'::regclass AND confrelid='aegaeon.end_users'::regclass AND contype='f'").fetch_one(&admin).await?;
        let delete_action: String = sqlx::query_scalar("SELECT confdeltype::text FROM pg_constraint WHERE conrelid='aegaeon.user_attribute_sources'::regclass AND confrelid='aegaeon.end_users'::regclass AND contype='f'").fetch_one(&admin).await?;
        assert_eq!(delete_action,"c","the installed migration must permit cascading deletion");
        for empty in [false,true] {
            let user = create_user(&pool, initialized.environment_id).await?;
            let subject: String = sqlx::query_scalar("SELECT subject FROM aegaeon.end_users WHERE id=$1").bind(user).fetch_one(&pool).await?;
            let uri = format!("/api/v1/teams/{}/environments/{}/users/{user}/attributes", initialized.team_id, initialized.environment_id);
            assert_eq!(put(&app,&uri,&session,0,json!({"value":"retained until deletion"}),None).await.status(),StatusCode::OK);
            if empty { assert_eq!(put(&app,&uri,&session,1,json!({}),None).await.status(),StatusCode::OK); }
            let snapshot = "SELECT jsonb_build_object('owners',(SELECT jsonb_agg(to_jsonb(o)) FROM aegaeon.end_user_identity_owners o WHERE owner_id=$1),'subjects',(SELECT jsonb_agg(to_jsonb(s) ORDER BY subject) FROM aegaeon.end_user_subject_reservations s WHERE owner_id=$1))";
            let before: Value = sqlx::query_scalar(snapshot).bind(user).fetch_one(&admin).await?;
            assert_eq!(before["owners"].as_array().map(Vec::len),Some(1));
            assert_eq!(before["subjects"].as_array().map(Vec::len),Some(1));
            if !empty {
                // Actual old FK negative control: a retained namespace blocks
                // physical deletion with NO ACTION, without deleting anything.
                sqlx::raw_sql(&format!("ALTER TABLE aegaeon.user_attribute_sources DROP CONSTRAINT {key}, ADD CONSTRAINT {key} FOREIGN KEY(environment_id,end_user_id) REFERENCES aegaeon.end_users(environment_id,id) ON DELETE NO ACTION")).execute(&admin).await?;
                let refused = sqlx::query("DELETE FROM aegaeon.end_users WHERE id=$1").bind(user).execute(&pool).await;
                assert!(matches!(refused,Err(sqlx::Error::Database(error)) if error.code().as_deref()==Some("23503")));
                assert_eq!(load_attribute_sources(&pool, initialized.environment_id, user).await?.len(),1);
                sqlx::raw_sql(&format!("ALTER TABLE aegaeon.user_attribute_sources DROP CONSTRAINT {key}, ADD CONSTRAINT {key} FOREIGN KEY(environment_id,end_user_id) REFERENCES aegaeon.end_users(environment_id,id) ON DELETE CASCADE")).execute(&admin).await?;
            }
            sqlx::query("DELETE FROM aegaeon.end_users WHERE id=$1").bind(user).execute(&pool).await?;
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.user_attribute_sources WHERE end_user_id=$1").bind(user).fetch_one(&pool).await?;
            assert_eq!(count,0);
            assert_eq!(get(&app,&uri,&session).await.status(),StatusCode::NOT_FOUND);
            for (id,subject,constraint) in [(user,"fresh-uuid-reuse".to_string(),"end_users_historical_uuid_reuse"),(Uuid::new_v4(),subject,"end_users_subject_owner_conflict")] {
                let refused=sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')").bind(id).bind(initialized.environment_id).bind(subject).execute(&pool).await;
                assert!(matches!(refused,Err(sqlx::Error::Database(error)) if error.code().as_deref()==Some("23505") && error.constraint()==Some(constraint)));
            }
            let after:Value=sqlx::query_scalar(snapshot).bind(user).fetch_one(&admin).await?;
            assert_eq!(before,after);
        }
        admin.close().await;
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_attribute_numeric_values_survive_database_and_response_roundtrip(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let (app, session) = authenticated_app(&pool).await?;
        let uri = format!(
            "/api/v1/teams/{}/environments/{}/users/{user}/attributes",
            initialized.team_id, initialized.environment_id
        );
        let values = json!({"numbers":[6.763905458681612e-289, 2.7896748684220982e56,
            -1.6949338398152967e286, 1e-300, 0.1, i64::MIN, u64::MAX]});
        let response = put(&app, &uri, &session, 0, values.clone(), None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1_048_576).await?;
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(body["source"]["values"], values);
        let sources = load_attribute_sources(&pool, initialized.environment_id, user).await?;
        assert_eq!(sources[0].values, values);
        let response = get(&app, &uri, &session).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1_048_576).await?;
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(body["sources"][0]["values"], values);
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}
