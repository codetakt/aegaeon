use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and actual witness retirement"]
async fn pg_organizations_retired_invitation_epoch_rejects_delivery_challenge_and_acceptance(
) -> TestResult {
    let f = InvitationFixture::new().await?;
    let mut witness = CallerFixture::new(f.base.env.environment_id)
        .await
        .map_err(|e| e.to_string())?;
    let result = exercise(&f, &mut witness).await;
    let cleanup = witness.finish().await.map_err(|e| e.to_string());
    f.base
        .cleanup(result.and(cleanup.map_err(Into::into)))
        .await
}

async fn exercise(f: &InvitationFixture, witness: &mut CallerFixture) -> TestResult {
    // Historical inspection requires its own explicit capability; provision alone is insufficient.
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"provision\",\"reconcile\"]'::jsonb,revision=revision+1 WHERE environment_id=$1 AND administrator_id=$2")
        .bind(f.base.env.environment_id).bind(f.base.actor.id).execute(&f.base.pool).await?;
    let first = witness.begin().await.map_err(|e| e.to_string())?;
    let (id, secret, challenge, proof) = first
        .store_scope(f.prepared())
        .await
        .map_err(|e| e.to_string())??;
    let retained: serde_json::Value = sqlx::query_scalar(
        "SELECT authority->'epoch' FROM aegaeon.organization_invitations WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&f.base.pool)
    .await?;
    assert_eq!(retained, serde_json::to_value(first.binding())?);
    for sql in [
        "UPDATE aegaeon.organization_invitations SET authority='{}'::jsonb WHERE id=$1",
        "UPDATE aegaeon.organization_invitation_challenges SET invitation_id=$1 WHERE id=$1",
        "UPDATE aegaeon.organization_identity_requests SET invitation_id=$1 WHERE id=$1",
    ] {
        let error = sqlx::query(sql)
            .bind(id)
            .execute(&f.base.pool)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501")
        );
    }
    first.complete().await.map_err(|e| e.to_string())?;
    witness.retire_epoch().await.map_err(|e| e.to_string())?;
    let second = witness.begin().await.map_err(|e| e.to_string())?;
    let checked = second
        .store_scope(check(f, id, &secret, challenge, &proof))
        .await
        .map_err(|e| e.to_string())?;
    let completed = second.complete().await.map_err(|e| e.to_string());
    checked?;
    assert_eq!(completed?.pending, 0);
    Ok(())
}

async fn check(
    f: &InvitationFixture,
    id: Uuid,
    secret: &str,
    challenge: Uuid,
    proof: &str,
) -> TestResult {
    let scope = f.base.organization.scope;
    let input = f.acceptance(id, secret, challenge, proof);
    let mut tx = f.base.pool.begin().await?;
    let delivery = invite::claim_invitation_delivery(&mut tx, scope, id, 161).await;
    tx.rollback().await?;
    if delivery.is_ok() {
        return Err("retired invitation cannot issue another delivery".into());
    }
    let mut tx = f.base.pool.begin().await?;
    assert!(invite::request_challenge(&mut tx, &input, "challenge-once")
        .await
        .is_err());
    assert!(
        invite::claim_challenge_delivery(&mut tx, scope, id, challenge, 163)
            .await
            .is_err()
    );
    assert!(invite::accept_first_admin(&mut tx, &input).await.is_err());
    assert!(
        invite::issue_first_admin(&mut tx, f.issuance())
            .await
            .is_err(),
        "replay cannot upgrade"
    );
    let historical = invite::read(&mut tx, scope, f.base.env.team_id, f.base.actor.id, id)
        .await
        .map_err(|error| format!("historical inspection: {error}"))?;
    assert_eq!(historical.id, id);
    let mut fresh = f.issuance();
    fresh.key = "fresh-epoch";
    let fresh = invite::issue_first_admin(&mut tx, fresh).await?;
    assert_ne!(fresh.id, id);
    invite::claim_invitation_delivery(&mut tx, scope, fresh.id, 101).await?;
    let revoked = invite::revoke(
        &mut tx,
        invite::Revocation {
            scope,
            team: f.base.env.team_id,
            actor: &f.base.actor,
            key: "retired-revoke",
            id,
            expected_revision: historical.revision,
        },
    )
    .await?;
    assert_eq!(revoked.state, invite::State::Revoked);
    tx.commit().await?;
    Ok(())
}
