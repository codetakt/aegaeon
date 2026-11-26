use super::*;
use axum::http::Method;

async fn manage(
    f: &RecipientFixture,
    sid: &str,
    method: Method,
    path: &str,
) -> TestResult<StatusCode> {
    let body = if method == Method::DELETE {
        Body::empty()
    } else {
        Body::from("{}")
    };
    let req = Request::builder()
        .method(method)
        .uri(format!(
            "/api/v1/teams/{}/environments/{}/users/{path}",
            f.base.env.team_id, f.state.environment_id
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "https://admin.example.com")
        .header(
            header::COOKIE,
            format!("aegaeon_admin_session={sid}; csrf_token=withdrawal-test"),
        )
        .header("x-csrf-token", "withdrawal-test")
        .body(body)?;
    // Independent management HTTP requests do not inherit the browser request's task scope.
    let app = crate::web::build_router(f.state.clone());
    Ok(tokio::spawn(async move { app.oneshot(req).await })
        .await??
        .status())
}

async fn registration(
    f: &RecipientFixture,
    key: &str,
    transport: &Transport,
) -> TestResult<(Uuid, String)> {
    let (status, body) = request(f, "registration", "", key).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["requestId"].as_str().ok_or("request id")?.parse()?;
    let envelope = delivered(f, id, transport).await?;
    Ok((
        id,
        envelope["capability"]
            .as_str()
            .ok_or("mail proof")?
            .to_owned(),
    ))
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL, Redis and the TLS mail receiver"]
async fn shared_redis_organizations_enrollment_withdrawal_releases_only_the_address() -> TestResult
{
    let mut f = setup::new().await?;
    Arc::make_mut(&mut f.state.management.cfg).allowed_origins =
        vec!["https://admin.example.com".into()];
    let sid = f
        .state
        .management
        .human_session_for_test(f.base.actor.id, crate::util::now_unix_epoch_secs()?)
        .ok_or("administrator session")?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, Box::pin(withdraw_and_register(&f, &sid))).await;
    drop(witness);
    f.finish(result).await
}

async fn withdraw_and_register(f: &RecipientFixture, sid: &str) -> TestResult {
    enable(f).await?;
    let transport = Transport::new(204, vec![], Duration::ZERO, false)?;
    let old = f.base.users[0];
    let old_subject = format!("organization-user-{old}");
    let old_password = "old-withdrawal-password";
    let old_hash = crate::local_credentials::hash_password(old_password)?;
    let pool = &f.base.pool;
    sqlx::query("UPDATE aegaeon.end_users SET email='invitee@example.test' WHERE id=$1")
        .bind(old)
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO aegaeon.end_user_profiles(end_user_id,verified_delivery_address,email_verified)
            VALUES($1,'Invitee@example.test',false)").bind(old).execute(pool).await?;
    sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash) VALUES($1,$2)")
            .bind(old).bind(old_hash).execute(pool).await?;
    let token_id: Uuid = sqlx::query_scalar(
        "INSERT INTO aegaeon.end_user_recovery_tokens(end_user_id,token_hash,purpose,expires_at)
            VALUES($1,$2,'password_reset',now()+interval '10 minutes') RETURNING id",
    )
    .bind(old)
    .bind(Uuid::new_v4().to_string())
    .fetch_one(pool)
    .await?;
    let (id, proof) = registration(f, "before-release", &transport).await?;
    let action = format!("{old}/finalizeWithdrawal");
    let restore = format!("{old}/restore");
    assert_eq!(
        manage(f, sid, Method::POST, &action).await?,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        manage(f, sid, Method::POST, &format!("{old}/suspend")).await?,
        StatusCode::OK
    );
    assert_eq!(
        manage(f, sid, Method::POST, &action).await?,
        StatusCode::NOT_FOUND
    );
    assert!(post(f, completion(id, &proof, PASSWORD), None)
        .await?
        .0
        .is_client_error());
    assert_eq!(
        manage(f, sid, Method::DELETE, &old.to_string()).await?,
        StatusCode::NO_CONTENT
    );
    assert!(post(f, completion(id, &proof, PASSWORD), None)
        .await?
        .0
        .is_client_error());
    assert_eq!(
        manage(f, sid, Method::POST, &restore).await?,
        StatusCode::OK
    );
    assert!(crate::local_credentials::authenticate_local_user(
        pool,
        &f.state.issuer,
        &old_subject,
        old_password
    )
    .await?
    .is_some());
    assert_eq!(
        manage(f, sid, Method::DELETE, &old.to_string()).await?,
        StatusCode::NO_CONTENT
    );
    let (one, two) = tokio::join!(
        manage(f, sid, Method::POST, &action),
        manage(f, sid, Method::POST, &action)
    );
    assert_eq!(
        (one?, two?),
        (StatusCode::NO_CONTENT, StatusCode::NO_CONTENT)
    );
    assert!(post(f, completion(id, &proof, PASSWORD), None)
        .await?
        .0
        .is_client_error());

    let (fresh, fresh_proof) = registration(f, "after-release", &transport).await?;
    assert_eq!(
        manage(f, sid, Method::POST, &action).await?,
        StatusCode::NO_CONTENT
    );
    let (status, body) = post(f, completion(fresh, &fresh_proof, PASSWORD), None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new_subject = body["subject"].as_str().ok_or("subject")?;
    assert_ne!(new_subject, old_subject);
    let account = crate::local_credentials::authenticate_local_user(
        pool,
        &f.state.issuer,
        "invitee@example.test",
        PASSWORD,
    )
    .await?
    .ok_or("new mailbox owner")?;
    assert_eq!(account.subject, new_subject);
    assert_ne!(account.end_user_id, old);
    let members: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.organization_memberships WHERE end_user_id=$1",
    )
    .bind(account.end_user_id)
    .fetch_one(pool)
    .await?;
    assert_eq!(members, 0);
    assert_eq!(
        manage(f, sid, Method::POST, &restore).await?,
        StatusCode::OK
    );
    let old_row:(String,Option<String>,String,Option<String>,bool)=sqlx::query_as("SELECT u.status::text,u.email,u.subject,p.verified_delivery_address,p.email_verified FROM aegaeon.end_users u JOIN aegaeon.end_user_profiles p ON p.end_user_id=u.id WHERE u.id=$1")
            .bind(old).fetch_one(pool).await?;
    assert_eq!(
        old_row,
        ("INVITED".into(), None, old_subject.clone(), None, false)
    );
    assert!(crate::local_credentials::authenticate_local_user(
        pool,
        &f.state.issuer,
        &old_subject,
        old_password
    )
    .await?
    .is_none());
    let revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM aegaeon.end_user_recovery_tokens WHERE id=$1",
    )
    .bind(token_id)
    .fetch_one(pool)
    .await?;
    assert!(revoked);
    assert!(crate::local_credentials::authenticate_local_user(
        pool,
        &f.state.issuer,
        new_subject,
        PASSWORD
    )
    .await?
    .is_some());
    Ok(())
}
