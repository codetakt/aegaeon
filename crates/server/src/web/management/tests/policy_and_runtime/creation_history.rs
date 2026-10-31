fn creation_http_request(
    f: &RenameHistoryFixture,
    key: &[&str],
    subject: &str,
) -> Result<axum::http::Request<Body>, Box<dyn StdError>> {
    let mut request = membership_http_request(
        Method::POST,
        &f.user.env,
        "users",
        &f.user.sid,
        serde_json::json!({"subject":subject,"email":"owner@example.com"}),
    )?;
    for value in key {
        request
            .headers_mut()
            .append("idempotency-key", value.parse()?);
    }
    Ok(request)
}

async fn creation_request(
    f: &RenameHistoryFixture,
    key: &[&str],
    subject: &str,
) -> Result<axum::response::Response, Box<dyn StdError>> {
    Ok(f.witness
        .run(
            f.user
                .app
                .clone()
                .oneshot(creation_http_request(f, key, subject)?),
        )
        .await??)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual management creation/replay/rename/deletion with independent retained owner"]
async fn pg_organizations_creation_management_replay() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let result=history_test(async {
        let key=Uuid::new_v4().to_string();
        let response=creation_request(&f,&[&key],"created").await?;assert_eq!(response.status(),StatusCode::CREATED);
        let user=response_json(response).await?;let id:Uuid=user["id"].as_str().ok_or("id")?.parse()?;
        let replay=creation_request(&f,&[&key],"created").await?;assert_eq!(replay.status(),StatusCode::OK);assert_eq!(response_json(replay).await?,user);
        assert_eq!(f.witness.retained_creation("created").await?,(id,"committed".into(),1));
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.user.created.v1' AND target_id=$2")
            .bind(f.user.env.environment_id).bind(id.to_string()).fetch_one(&f.user.runtime).await?;assert_eq!(count,1);
        f.witness.run(f.user.rename(id,"renamed")).await??;
        let replay=creation_request(&f,&[&key],"created").await?;assert_eq!(replay.status(),StatusCode::OK);assert_eq!(response_json(replay).await?["subject"],"renamed");
        let deleted=f.user.send(Method::DELETE,&format!("users/{id}"),serde_json::json!({})).await?;assert!(deleted.status().is_success());
        let replay=creation_request(&f,&[&key],"created").await?;assert_eq!(replay.status(),StatusCode::NOT_FOUND);
        assert_eq!(f.witness.retained_creation("created").await?,(id,"committed".into(),1));
        assert_eq!(f.witness.pending().await?,0);
        Ok(())
    }).await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; canonical unique idempotency header and immutable payload binding"]
async fn pg_organizations_creation_management_input_confusion() -> TestResult {
    let f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let key = Uuid::new_v4().to_string();
        let upper = key.to_uppercase();
        let padded = format!(" {key}");
        let nil = Uuid::nil().to_string();
        let before = f.user.snapshot().await?;
        for keys in [
            vec![],
            vec!["bad"],
            vec![nil.as_str()],
            vec![upper.as_str()],
            vec![padded.as_str()],
            vec![key.as_str(), key.as_str()],
        ] {
            let response = creation_request(&f, &keys, "bound").await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        assert_eq!(f.user.snapshot().await?, before);
        assert_eq!(
            creation_request(&f, &[&key], "bound").await?.status(),
            StatusCode::CREATED
        );
        let before = f.user.snapshot().await?;
        assert_eq!(
            creation_request(&f, &[&key], "Bound").await?.status(),
            StatusCode::CONFLICT
        );
        assert_eq!(f.user.snapshot().await?, before);
        assert_eq!(
            creation_request(&f, &[&Uuid::new_v4().to_string()], "bound")
                .await?
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(f.user.snapshot().await?, before);
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; confirmed audit rollback retries the retained original creation owner"]
async fn pg_organizations_creation_management_primary_rollback() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let key = Uuid::new_v4().to_string();
    let name = format!("creation_failure_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id='{}'::uuid AND NEW.event_type='management.user.created.v1' THEN RAISE EXCEPTION 'injected creation audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.{name}()",f.user.env.environment_id)).execute(&f.user.admin).await?;
    let result = history_test(async {
        let before = f.user.snapshot().await?;
        let response = creation_request(&f, &[&key], "rollback").await?;
        assert!(!response.status().is_success());
        assert_eq!(f.user.snapshot().await?, before);
        let (id, state, attempt) = f.witness.retained_creation("rollback").await?;
        assert_eq!((state, attempt), ("retryable".into(), 1));
        assert_eq!(f.witness.retained_subjects(id).await?, vec!["rollback"]);
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    let cleanup = sqlx::raw_sql(&format!(
        "DROP TRIGGER {name} ON aegaeon.audit_events; DROP FUNCTION aegaeon.{name}()"
    ))
    .execute(&f.user.admin)
    .await;
    let result = history_test(async {
        result?;
        cleanup?;
        let (id, _, _) = f.witness.retained_creation("rollback").await?;
        let response = creation_request(&f, &[&key], "rollback").await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response_json(response).await?["id"], id.to_string());
        assert_eq!(
            f.witness.retained_creation("rollback").await?,
            (id, "committed".into(), 2)
        );
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; committed role revocation after allocation prevents primary creation"]
async fn pg_organizations_creation_management_current_authority() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let key = Uuid::new_v4().to_string();
    let result=history_test(async {
        let mut barrier=f.witness.history_append_barrier().await?;
        let keys=[key.as_str()];let call=creation_request(&f,&keys,"revoked");tokio::pin!(call);
        let controller=async {
            let observed=f.witness.wait_for_creation_prepare().await;
            let revoked=sqlx::query("UPDATE aegaeon.team_memberships SET role='AUDITOR' WHERE team_id=$1 AND administrator_id=$2")
                .bind(f.user.env.team_id).bind(f.user.env.administrator_id).execute(&f.user.admin).await;
            let release=sqlx::query("ROLLBACK").execute(&mut barrier).await;
            let close=sqlx::Connection::close(barrier).await;
            observed?;revoked?;release?;close?;Ok::<(),Box<dyn StdError>>(())
        };
        let (response,controlled)=tokio::join!(&mut call,controller);controlled?;assert_eq!(response?.status(),StatusCode::FORBIDDEN);
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1 AND subject='revoked'").bind(f.user.env.environment_id).fetch_one(&f.user.runtime).await?;assert_eq!(count,0);
        Ok(())
    }).await;
    let restored = sqlx::query(
        "UPDATE aegaeon.team_memberships SET role='OWNER' WHERE team_id=$1 AND administrator_id=$2",
    )
    .bind(f.user.env.team_id)
    .bind(f.user.env.administrator_id)
    .execute(&f.user.admin)
    .await;
    let result = history_test(async {
        result?;
        restored?;
        let (id, state, attempt) = f.witness.retained_creation("revoked").await?;
        assert_eq!((state, attempt), ("retryable".into(), 1));
        let response = creation_request(&f, &[&key], "revoked").await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response_json(response).await?["id"], id.to_string());
        Ok(())
    })
    .await;
    f.finish(result).await
}

include!("creation_history/failures.rs");
include!("creation_history/receipt.rs");
mod creation_transport {
    use super::*;
    include!("creation_history/transport.rs");
}
