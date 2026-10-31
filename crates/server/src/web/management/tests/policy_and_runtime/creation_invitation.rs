async fn retained_invite_request(
    f: &RenameHistoryFixture,
    keys: &[&str],
    body: serde_json::Value,
) -> Result<axum::response::Response, Box<dyn StdError>> {
    let mut request = membership_http_request(
        Method::POST,
        &f.user.env,
        "users/invitations",
        &f.user.sid,
        body,
    )?;
    for key in keys {
        request
            .headers_mut()
            .append("idempotency-key", key.parse()?);
    }
    Ok(f.witness.run(f.user.app.clone().oneshot(request)).await??)
}

async fn retained_invite_counts(
    f: &RenameHistoryFixture,
) -> Result<(i64, i64, i64), Box<dyn StdError>> {
    Ok(sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1 AND subject='invite'),(SELECT count(*) FROM aegaeon.end_user_recovery_tokens r JOIN aegaeon.end_users u ON u.id=r.end_user_id WHERE u.environment_id=$1),(SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.user.invited.v1')")
        .bind(f.user.env.environment_id).fetch_one(&f.user.runtime).await?)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; retained invitation exposes one activation secret and refuses duplicate issuance"]
async fn pg_organizations_creation_invitation_one_time_replay() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let key = Uuid::new_v4().to_string();
        let body = serde_json::json!({"subject":"invite","email":"invite@example.com"});
        let response = retained_invite_request(&f, &[&key], body.clone()).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let value = response_json(response).await?;
        let id: Uuid = value["user"]["id"].as_str().ok_or("user id")?.parse()?;
        let token = value["activation"]["token"]
            .as_str()
            .ok_or("activation token")?;
        assert_eq!(
            f.witness.retained_creation("invite").await?,
            (id, "committed".into(), 1)
        );
        assert_eq!(retained_invite_counts(&f).await?, (1, 1, 1));
        let replay = retained_invite_request(&f, &[&key], body.clone()).await?;
        assert_eq!(replay.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(replay).await?["errorCode"],
            "one_time_result_unavailable"
        );
        assert_eq!(retained_invite_counts(&f).await?, (1, 1, 1));
        let hash = crate::local_credentials::hash_password("valid-invitation-password")?;
        let issuer = format!("https://{}", f.user.env.issuer_host);
        let redeemed = f
            .witness
            .run(crate::local_credentials::redeem_recovery_token(
                &f.user.runtime,
                &issuer,
                token,
                crate::local_credentials::RecoveryTokenPurpose::Activation,
                &hash,
                "retained-invite-redeem",
            ))
            .await??;
        assert_eq!(redeemed.ok_or("activation refused")?.subject, "invite");
        let replay = f
            .witness
            .run(crate::local_credentials::redeem_recovery_token(
                &f.user.runtime,
                &issuer,
                token,
                crate::local_credentials::RecoveryTokenPurpose::Activation,
                &hash,
                "retained-invite-replay",
            ))
            .await??;
        assert!(replay.is_none());
        assert_eq!(
            retained_invite_request(&f, &[&key], body.clone())
                .await?
                .status(),
            StatusCode::CONFLICT
        );
        let deleted = f
            .user
            .send(
                Method::DELETE,
                &format!("users/{id}"),
                serde_json::json!({}),
            )
            .await?;
        assert!(deleted.status().is_success());
        assert_eq!(
            retained_invite_request(&f, &[&key], body).await?.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; invitation key, payload, TTL and creation kind remain distinct"]
async fn pg_organizations_creation_invitation_binding() -> TestResult {
    let f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let key = Uuid::new_v4().to_string();
        let body = serde_json::json!({"subject":"invite","expiresInSeconds":300});
        for keys in [vec![], vec!["bad"], vec![key.as_str(), key.as_str()]] {
            assert_eq!(
                retained_invite_request(&f, &keys, body.clone())
                    .await?
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        for ttl in [0, -1, 1, 299, 604_801, i64::MAX] {
            assert_eq!(
                retained_invite_request(
                    &f,
                    &[&key],
                    serde_json::json!({"subject":"invite","expiresInSeconds":ttl})
                )
                .await?
                .status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(retained_invite_counts(&f).await?, (0, 0, 0));
        // Same key, different kind: both independently retain their own owner.
        assert_eq!(
            creation_request(&f, &[&key], "create-kind").await?.status(),
            StatusCode::CREATED
        );
        assert_eq!(
            retained_invite_request(&f, &[&key], body.clone())
                .await?
                .status(),
            StatusCode::OK
        );
        assert_eq!(retained_invite_counts(&f).await?, (1, 1, 1));
        for changed in [
            serde_json::json!({"subject":"invite","expiresInSeconds":301}),
            serde_json::json!({"subject":"invite"}),
            serde_json::json!({"subject":"Invite","expiresInSeconds":300}),
        ] {
            assert_eq!(
                retained_invite_request(&f, &[&key], changed)
                    .await?
                    .status(),
                StatusCode::CONFLICT
            );
        }
        assert_eq!(retained_invite_counts(&f).await?, (1, 1, 1));
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; invitation rollback retains owner without retaining or issuing a secret"]
async fn pg_organizations_creation_invitation_rollback() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let key = Uuid::new_v4().to_string();
    let body = serde_json::json!({"subject":"invite"});
    let name = format!("invite_failure_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id='{}'::uuid AND NEW.event_type='management.user.invited.v1' THEN RAISE EXCEPTION 'injected invitation audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.{name}()",f.user.env.environment_id)).execute(&f.user.admin).await?;
    let result = history_test(async {
        assert!(!retained_invite_request(&f, &[&key], body.clone())
            .await?
            .status()
            .is_success());
        let (_, state, attempt) = f.witness.retained_creation("invite").await?;
        assert_eq!((state, attempt), ("retryable".into(), 1));
        assert_eq!(retained_invite_counts(&f).await?, (0, 0, 0));
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
        let (id, _, _) = f.witness.retained_creation("invite").await?;
        let response = retained_invite_request(&f, &[&key], body).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await?["user"]["id"], id.to_string());
        assert_eq!(
            f.witness.retained_creation("invite").await?,
            (id, "committed".into(), 2)
        );
        assert_eq!(retained_invite_counts(&f).await?, (1, 1, 1));
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; committed authority revocation after allocation blocks invitation and activation issuance"]
async fn pg_organizations_creation_invitation_current_authority() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let key = Uuid::new_v4().to_string();
    let body = serde_json::json!({"subject":"invite"});
    let result=history_test(async {
        let mut barrier=f.witness.history_append_barrier().await?;
        let keys=[key.as_str()];let call=retained_invite_request(&f,&keys,body.clone());tokio::pin!(call);
        let control=async {
            let observed=f.witness.wait_for_creation_prepare().await;
            let revoked=sqlx::query("UPDATE aegaeon.team_memberships SET role='AUDITOR' WHERE team_id=$1 AND administrator_id=$2").bind(f.user.env.team_id).bind(f.user.env.administrator_id).execute(&f.user.admin).await;
            let release=sqlx::query("ROLLBACK").execute(&mut barrier).await;
            let close=sqlx::Connection::close(barrier).await;
            observed?;revoked?;release?;close?;Ok::<(),Box<dyn StdError>>(())
        };
        let(response,control)=tokio::join!(&mut call,control);control?;assert_eq!(response?.status(),StatusCode::FORBIDDEN);
        assert_eq!(retained_invite_counts(&f).await?,(0,0,0));
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
        let (id, state, attempt) = f.witness.retained_creation("invite").await?;
        assert_eq!((state, attempt), ("retryable".into(), 1));
        let response = retained_invite_request(&f, &[&key], body).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await?["user"]["id"], id.to_string());
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; current TTL policy is enforced after allocation without rebinding the original request"]
async fn pg_organizations_creation_invitation_current_policy() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let key = Uuid::new_v4().to_string();
    let body = serde_json::json!({"subject":"invite","expiresInSeconds":600});
    let original: (i32,i32,i32) = sqlx::query_as("SELECT activation_token_default_ttl_seconds,password_reset_token_default_ttl_seconds,recovery_token_max_ttl_seconds FROM aegaeon.environment_policies WHERE environment_id=$1")
        .bind(f.user.env.environment_id).fetch_one(&f.user.admin).await?;
    let result = history_test(async {
        let mut barrier = f.witness.history_append_barrier().await?;
        let keys = [key.as_str()];
        let call = retained_invite_request(&f, &keys, body.clone());
        tokio::pin!(call);
        let control = async {
            let observed = f.witness.wait_for_creation_prepare().await;
            let altered = sqlx::query("UPDATE aegaeon.environment_policies SET activation_token_default_ttl_seconds=300,password_reset_token_default_ttl_seconds=300,recovery_token_max_ttl_seconds=300 WHERE environment_id=$1")
                .bind(f.user.env.environment_id).execute(&f.user.admin).await;
            let release = sqlx::query("ROLLBACK").execute(&mut barrier).await;
            let close = sqlx::Connection::close(barrier).await;
            observed?;
            altered?;
            release?;
            close?;
            Ok::<(), Box<dyn StdError>>(())
        };
        let (response, control) = tokio::join!(&mut call, control);
        control?;
        assert_eq!(response?.status(), StatusCode::BAD_REQUEST);
        assert_eq!(retained_invite_counts(&f).await?, (0, 0, 0));
        Ok(())
    })
    .await;
    let restored = sqlx::query("UPDATE aegaeon.environment_policies SET activation_token_default_ttl_seconds=$2,password_reset_token_default_ttl_seconds=$3,recovery_token_max_ttl_seconds=$4 WHERE environment_id=$1")
        .bind(f.user.env.environment_id).bind(original.0).bind(original.1).bind(original.2).execute(&f.user.admin).await;
    let result = history_test(async {
        result?;
        restored?;
        let (id, state, attempt) = f.witness.retained_creation("invite").await?;
        assert_eq!((state, attempt), ("retryable".into(), 1));
        let response = retained_invite_request(&f, &[&key], body).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await?["user"]["id"], id.to_string());
        assert_eq!(
            f.witness.retained_creation("invite").await?,
            (id, "committed".into(), 2)
        );
        assert_eq!(f.witness.pending().await?, 0);
        Ok(())
    })
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; current invitation policy and issuer remain locked until primary commit"]
async fn pg_organizations_creation_invitation_current_locks() -> TestResult {
    let mut f = RenameHistoryFixture::new().await?;
    let result = history_test(async {
        let mut barrier = f.user.admin.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.organization_creation_receipts IN SHARE MODE")
            .execute(&mut *barrier).await?;
        let work = f.witness.begin().await?;
        let label = work.admission().store_label()?.ok_or("work label")?.to_owned();
        let owner = work.admission().clone();
        let app = f.user.app.clone();
        let mut request = membership_http_request(Method::POST, &f.user.env, "users/invitations", &f.user.sid, serde_json::json!({"subject":"invite"}))?;
        request.headers_mut().insert("idempotency-key", Uuid::new_v4().to_string().parse()?);
        let execution = tokio::spawn(async move { owner.store_scope(app.oneshot(request)).await });
        let observed = creation_primary_wait(&f.user.admin, &label).await;
        let conflicts = async {
            observed?;
            let mut blocked = Vec::new();
            for statement in [
                "UPDATE aegaeon.environment_policies SET recovery_token_max_ttl_seconds=recovery_token_max_ttl_seconds WHERE environment_id=$1",
                "UPDATE aegaeon.environments SET name=name WHERE id=$1",
                "UPDATE aegaeon.tenants SET name=name WHERE id=(SELECT tenant_id FROM aegaeon.environments WHERE id=$1)",
            ] {
                let mut change = f.user.admin.begin().await?;
                sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *change).await?;
                let result = sqlx::query(statement).bind(f.user.env.environment_id).execute(&mut *change).await;
                let rejected = result.as_ref().err().and_then(sqlx::Error::as_database_error)
                    .and_then(|error| error.code()).is_some_and(|code| code == "55P03");
                change.rollback().await?;
                blocked.push(rejected);
            }
            Ok::<_,Box<dyn StdError>>(blocked)
        }.await;
        let released = barrier.rollback().await;
        let response = execution.await;
        released?;
        assert_eq!(response???.status(), StatusCode::OK);
        assert_eq!(work.complete().await?.pending, 0);
        assert_eq!(conflicts?, vec![true, true, true]);
        assert_eq!(retained_invite_counts(&f).await?, (1, 1, 1));
        Ok(())
    }).await;
    f.finish(result).await
}
