use super::*;

const V2: &str = "application/vnd.aegaeon.invitation-challenge.v2+json";

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_recipient_challenge_budget_and_replay() -> TestResult {
    let f = setup::new().await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, exercise_budget(&f)).await;
    drop(witness);
    f.finish(result).await
}

async fn exercise_budget(f: &RecipientFixture) -> TestResult {
    let signing_key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let (_, token) = f.token(&signing_key).await?;
    let other_key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let (_, other_token) = f.token(&other_key).await?;
    let first_device = (&signing_key, token.as_str());
    let second_device = (&other_key, other_token.as_str());
    let post = async |device: (&aegaeon_crypto::signing::Ed25519KeyData, &str),
                      operation: &str,
                      capability: &str,
                      key: Option<&str>,
                      accept: Option<&str>| {
        let path = f.path(operation);
        let proof = f.proof(device.0, device.1, &path)?;
        let mut request = Request::post(&path);
        if let Some(key) = key {
            request = request.header("Idempotency-Key", key);
        }
        if let Some(accept) = accept {
            request = request.header(header::ACCEPT, accept);
        }
        f.post_with_headers(
            device.1,
            Some(&proof),
            &json!({"invitationCapability":capability}),
            request,
        )
        .await
    };
    let status = async || post(first_device, "challenge-status", &f.capability, None, None).await;
    let allocate = async |device: (&aegaeon_crypto::signing::Ed25519KeyData, &str), key: &str| {
        post(device, "challenges", &f.capability, Some(key), Some(V2)).await
    };

    assert_eq!(
        post(first_device, "challenge-status", "invalid", None, None)
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    let refused = post(
        first_device,
        "challenges",
        &f.capability,
        Some("unused"),
        Some("text/plain"),
    )
    .await?;
    assert_eq!(refused.0, StatusCode::NOT_ACCEPTABLE);
    assert_eq!(refused.1[header::VARY], "Accept");
    let (code, _, before) = status().await?;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(before.as_object().ok_or("status")?.len(), 2);
    assert_eq!(before["remainingChallenges"], 5);
    assert_eq!(status().await?.2, before);
    let (code, headers, first) = allocate(first_device, "first").await?;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], V2);
    assert_eq!(headers[header::VARY], "Accept");
    assert_eq!(first.as_object().ok_or("allocation")?.len(), 3);
    assert_eq!(first["remainingChallenges"], 4);
    let now = i64::try_from(crate::util::now_unix_epoch_secs()?)?;
    let deadline = first["expiresAt"].as_i64().ok_or("expiry")?;
    assert!(now < deadline && deadline <= now + 300);
    assert!(
        deadline
            <= before["invitationExpiresAt"]
                .as_i64()
                .ok_or("invitation expiry")?
    );

    let (code, headers, legacy) = post(
        second_device,
        "challenges",
        &f.capability,
        Some("second"),
        Some("*/*"),
    )
    .await?;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(headers[header::VARY], "Accept");
    assert_eq!(legacy.as_object().ok_or("legacy allocation")?.len(), 1);
    assert_ne!(legacy["challengeId"], first["challengeId"]);
    let replay = allocate(first_device, "first").await?.2;
    assert_eq!(replay["challengeId"], first["challengeId"]);
    assert_eq!(replay["expiresAt"], first["expiresAt"]);
    assert_eq!(replay["remainingChallenges"], 3);
    for key in ["third", "fourth"] {
        assert_eq!(allocate(first_device, key).await?.0, StatusCode::OK);
    }
    let (a, b) = tokio::join!(
        allocate(first_device, "candidate-a"),
        allocate(second_device, "candidate-b")
    );
    let (a, b) = (a?, b?);
    let (winner, key, device, loser) = if a.0 == StatusCode::OK {
        (a, "candidate-a", first_device, b)
    } else {
        (b, "candidate-b", second_device, a)
    };
    assert_eq!(winner.0, StatusCode::OK);
    assert_eq!(winner.2["remainingChallenges"], 0);
    assert_eq!(loser.0, StatusCode::CONFLICT);
    assert_eq!(allocate(device, key).await?.2, winner.2);
    assert_eq!(status().await?.2["remainingChallenges"], 0);
    assert_eq!(
        allocate(second_device, "after-exhaustion").await?.0,
        StatusCode::CONFLICT
    );
    let allocated: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.organization_invitation_challenges WHERE invitation_id=$1",
    )
    .bind(f.invitation)
    .fetch_one(&f.base.pool)
    .await?;
    assert_eq!(allocated, 5);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.recipient_challenge_requested'")
            .bind(f.organization.id).fetch_one(&f.base.pool).await?;
    assert_eq!(count, 5);
    Ok(())
}
