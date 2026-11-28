use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_preview_distinguishes_equal_names_in_one_domain() -> TestResult
{
    let mut f = setup::hosted(OWNER).await?;
    let witness = Arc::clone(&f.witness);
    let result = in_epoch(&witness, compare(&mut f)).await;
    drop(witness);
    f.finish(result).await
}

async fn compare(f: &mut RecipientFixture) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let (_, token) = f.token(&key).await?;
    let preview = async |f: &RecipientFixture| {
        let (challenge, capability) = f.challenge(&key, &token).await?;
        let body = json!({"invitationCapability":f.capability,"challengeId":challenge,"challengeCapability":capability});
        let path = f.path("preview");
        let proof = f.proof(&key, &token, &path)?;
        let (status, _, body) = f
            .post_with_headers(&token, Some(&proof), &body, Request::post(path))
            .await?;
        assert_eq!(status, StatusCode::OK);
        Ok::<_, Box<dyn std::error::Error>>(body)
    };
    let original = preview(f).await?;
    let peer = Organization {
        id: Uuid::new_v4(),
        external_id: "other-school".into(),
        ..f.organization.clone()
    };
    let scope = peer.scope;
    let mut tx = f.base.pool.begin().await?;
    crate::organizations::repository::create_organization(&mut tx, &peer, &f.base.actor).await?;
    sqlx::query("UPDATE aegaeon.application_organizations SET display_name='School',display_revision=1 WHERE id=$1")
        .bind(peer.id).execute(&mut *tx).await?;
    let pin: Uuid = sqlx::query_scalar(
        "SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2",
    )
    .bind(scope.environment_id)
    .bind(OWNER)
    .fetch_one(&mut *tx)
    .await?;
    let now = i64::try_from(crate::util::now_unix_epoch_secs()?)?;
    let invitation = service::issue::for_profile(
        &mut tx,
        service::Issuance {
            scope,
            team: f.base.env.team_id,
            actor: &f.base.actor,
            key: "same-name-peer",
            now,
            request: &service::FirstAdminRequest {
                organization_id: peer.id,
                expected_revision: peer.revision,
                recipient: "Invitee@example.test".into(),
                roles: std::collections::BTreeSet::from(["admin".into()]),
                lifetime_seconds: Some(3600),
            },
        },
        Some(pin),
    )
    .await?;
    let mail = service::claim_invitation_delivery(&mut tx, scope, invitation.id, now).await?;
    tx.commit().await?;
    let original_id = f.organization.id;
    f.organization = peer;
    f.invitation = invitation.id;
    f.capability = mail.capability.into_delivery();
    let second = preview(f).await?;
    assert_eq!(original["organizationId"], original_id.to_string());
    assert_eq!(second["organizationId"], f.organization.id.to_string());
    assert_ne!(original["organizationId"], second["organizationId"]);
    for value in [original, second] {
        assert_eq!(value["issuer"], f.state.issuer.as_str());
        assert_eq!(value["organizationName"], "School");
        assert_eq!(
            value["roles"],
            json!([{"key":"admin","label":"Administrator"}])
        );
    }
    Ok(())
}
