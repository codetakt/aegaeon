use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_conditional_preview_and_response_loss() -> TestResult {
    let f = setup::hosted(OWNER).await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, confirm(&f)).await;
    drop(witness);
    f.finish(result).await
}

async fn confirm(f: &RecipientFixture) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let (_, token) = f.token(&key).await?;
    let role = async |label: Option<&str>| {
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET display_label=$1,display_revision=display_revision+1 WHERE domain_id=$2 AND role_key='admin'").bind(label).bind(f.organization.scope.domain_id).execute(&f.base.pool).await
    };
    let post = async |op: &str, body: &Value, tag: Option<&str>| {
        let path = f.path(op);
        let proof = f.proof(&key, &token, &path)?;
        let mut req = Request::post(&path).header("Idempotency-Key", "recipient-challenge");
        if let Some(tag) = tag {
            req = req.header(header::IF_MATCH, tag);
        }
        f.post_with_headers(&token, Some(&proof), body, req).await
    };
    role(None).await?;
    let refused = post(
        "challenges",
        &json!({"invitationCapability":f.capability}),
        None,
    )
    .await?;
    assert_eq!(refused.0, StatusCode::CONFLICT);
    assert_eq!(refused.2["error"], "display_metadata_unavailable");
    role(Some("Administrator")).await?;
    let (challenge, secret) = f.challenge(&key, &token).await?;
    let body = json!({"invitationCapability":f.capability,"challengeId":challenge,"challengeCapability":secret});
    let initial = post("preview", &body, None).await?;
    assert_eq!(initial.0, StatusCode::OK);
    assert_eq!(
        initial.2,
        json!({"issuer":f.state.issuer,"organizationId":f.organization.id,"organizationName":"School","roles":[{"key":"admin","label":"Administrator"}]})
    );
    let first = initial.1[header::ETAG].to_str()?;
    let bad_proof = json!({"invitationCapability":f.capability,"challengeId":challenge,"challengeCapability":f.capability});
    for tag in [None, Some("*"), Some(first)] {
        let denied = post("accept", &bad_proof, tag).await?;
        assert_eq!(denied.0, StatusCode::FORBIDDEN);
        assert_eq!(denied.2["error"], "insufficient_scope");
        assert!(denied.1.get(header::ETAG).is_none());
    }
    let other_rows=sqlx::query("UPDATE aegaeon.organization_role_definitions SET display_label='Unrelated label',display_revision=display_revision+1 WHERE domain_id=$1 AND role_key <> 'admin'").bind(f.organization.scope.domain_id).execute(&f.base.pool).await?.rows_affected();
    assert!(other_rows > 0);
    let members = sqlx::query(
        "UPDATE aegaeon.organization_memberships SET revision=revision+1 WHERE organization_id=$1",
    )
    .bind(f.base.organization.id)
    .execute(&f.base.pool)
    .await?
    .rows_affected();
    assert!(members > 0);
    assert_eq!(post("preview", &body, None).await?.1[header::ETAG], first);
    assert_eq!(
        post("accept", &body, None).await?.0,
        StatusCode::PRECONDITION_REQUIRED
    );
    for tag in ["*", "W/\"weak\"", "\"a\", \"b\""] {
        assert_eq!(
            post("accept", &body, Some(tag)).await?.0,
            StatusCode::BAD_REQUEST
        );
    }
    role(None).await?;
    for op in ["preview", "accept"] {
        let refused = post(op, &body, Some(first)).await?;
        assert_eq!(refused.0, StatusCode::CONFLICT);
        assert_eq!(refused.2["error"], "display_metadata_unavailable");
        assert!(refused.1.get(header::ETAG).is_none());
    }
    role(Some("Administrator")).await?;
    assert_eq!(
        post("accept", &body, Some(first)).await?.0,
        StatusCode::PRECONDITION_FAILED
    );
    let fresh = post("preview", &body, None).await?;
    assert_eq!(fresh.2, initial.2);
    let tag = fresh.1[header::ETAG].to_str()?;
    assert_ne!(tag, first);
    sqlx::query("UPDATE aegaeon.application_organizations SET revision=revision+1 WHERE id=$1")
        .bind(f.organization.id)
        .execute(&f.base.pool)
        .await?;
    assert_eq!(
        post("accept", &body, Some(tag)).await?.0,
        StatusCode::PRECONDITION_FAILED
    );
    let new_view = post("preview", &body, None).await?;
    let tag = new_view.1[header::ETAG].to_str()?;
    let accepted = post("accept", &body, Some(tag)).await?;
    assert_eq!(accepted.0, StatusCode::OK);
    let retained: Value = sqlx::query_scalar(
        "SELECT to_jsonb(i) FROM aegaeon.organization_invitations i WHERE id=$1",
    )
    .bind(f.invitation)
    .fetch_one(&f.base.pool)
    .await?;
    assert_eq!(retained["result"]["validator"], tag);
    assert_eq!(retained["accepted_challenge_id"], challenge.to_string());
    role(None).await?;
    assert_eq!(post("preview", &body, None).await?.0, StatusCode::FORBIDDEN);
    assert_eq!(
        post("accept", &body, Some(first)).await?.0,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        post("accept", &body, None).await?.0,
        StatusCode::PRECONDITION_REQUIRED
    );
    assert_eq!(post("accept", &body, Some(tag)).await?.2, accepted.2);
    let effects:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.invitation_accepted'").bind(f.organization.id).fetch_one(&f.base.pool).await?;
    let allocated: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.organization_invitation_challenges WHERE invitation_id=$1",
    )
    .bind(f.invitation)
    .fetch_one(&f.base.pool)
    .await?;
    assert_eq!((effects, allocated), (1, 1));
    sqlx::query("UPDATE aegaeon.organization_memberships SET revision=revision+1 WHERE organization_id=$1 AND end_user_id=$2").bind(f.organization.id).bind(f.base.users[1]).execute(&f.base.pool).await?;
    assert_eq!(
        post("accept", &body, Some(tag)).await?.0,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_wrong_hosted_client_refusals() -> TestResult {
    let f = setup::hosted(RS).await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, compare_refusals(&f)).await;
    drop(witness);
    f.finish(result).await
}

async fn compare_refusals(f: &RecipientFixture) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let (_, token) = f.token(&key).await?;
    let unknown = Uuid::new_v4();
    let challenge = Uuid::new_v4();
    for action in ["challenge-status", "challenges", "preview", "accept"] {
        let body = match action {
            "preview" | "accept" => {
                json!({"invitationCapability":f.capability,"challengeId":challenge,"challengeCapability":f.capability})
            }
            _ => json!({"invitationCapability":f.capability}),
        };
        let send = async |id: Uuid, tag: Option<&str>| {
            let path = format!(
                "/organization-invitations/{}/{id}/{action}",
                f.organization.scope.domain_id
            );
            let proof = f.proof(&key, &token, &path)?;
            let mut req = Request::post(&path)
                .header("Idempotency-Key", "wrong-client")
                .header("x-request-id", "same-refusal");
            if let Some(tag) = tag {
                req = req.header(header::IF_MATCH, tag);
            }
            f.post_with_headers(&token, Some(&proof), &body, req).await
        };
        let baseline = send(unknown, None).await?;
        assert_eq!(baseline.0, StatusCode::FORBIDDEN);
        assert_eq!(baseline.2["error"], "insufficient_scope");
        for tag in [None, Some("*"), Some("\"mismatch\"")] {
            assert_eq!(send(f.invitation, tag).await?, baseline);
            assert_eq!(send(unknown, tag).await?, baseline);
        }
    }
    Ok(())
}
