//! Invitation-bound identity proofs use the same atomic encrypted producer.
use super::super::durable::{self as notification, Producer, Proof};
use super::*;

pub(in crate::organizations::invitations) async fn current_for_send(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    invitation: Uuid,
    id: Uuid,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<notification::CurrentProof, RepositoryError> {
    // pending takes the policy lock before the principal/domain/object locks.
    let pending = pending(tx, scope, invitation, id, now, runtime).await?;
    require(pending.result.is_none())?;
    if let Some((user, revision)) = pending.target {
        let row = sqlx::query("SELECT u.organization_identity_revision AS revision,u.email,p.email_verified,p.verified_delivery_address FROM aegaeon.end_users u JOIN aegaeon.end_user_password_credentials c ON c.end_user_id=u.id AND c.status='ACTIVE' JOIN aegaeon.end_user_profiles p ON p.end_user_id=u.id WHERE u.environment_id=$1 AND u.id=$2 AND u.status='ACTIVE' FOR SHARE OF u,c,p")
            .bind(scope.environment_id).bind(user).fetch_optional(&mut **tx).await?
            .ok_or(AuthorityError::Forbidden)?;
        require(
            row.try_get::<i64, _>("revision")? == revision
                && verified_address(&row, &pending.invitation.recipient)?,
        )?;
    }
    Ok(notification::CurrentProof {
        invitation: pending.invitation,
        revision: pending.revision,
        delivered_at: pending.delivered_at,
        purpose: pending.purpose.capability(),
        expires_at: pending.expires,
        hash: pending.hash.unwrap_or_default(),
        purpose_binding: serde_json::json!({
            "policyRevision":pending.policy_revision,"target":pending.target,
        }),
    })
}

pub(super) async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    input: &Request<'_>,
    id: Uuid,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<(), RepositoryError> {
    let pending = pending(tx, input.scope, input.invitation, id, input.now, runtime).await?;
    let Some(producer) = Producer::current(tx, input.scope).await? else {
        return Ok(());
    };
    require(pending.result.is_none() && pending.revision == 0 && pending.hash.is_none())?;
    let purpose = pending.purpose.capability();
    let (capability, hash) = super::super::delivery::generate(input.scope, id, 1, purpose)?;
    let changed = sqlx::query("UPDATE aegaeon.organization_identity_requests SET delivery_revision=1,delivered_at=$2,capability_hash=$3,delivery_outcome='uncertain' WHERE id=$1 AND delivery_revision=0")
        .bind(id).bind(input.now).bind(hash.as_slice()).execute(&mut **tx).await?;
    require(changed.rows_affected() == 1)?;
    let message = producer
        .enqueue(
            tx,
            Proof {
                scope: input.scope,
                invitation: &pending.invitation,
                object_id: id,
                revision: 1,
                purpose,
                expires_at: pending.expires,
                hash: &hash,
                purpose_binding: serde_json::json!({
                    "policyRevision":pending.policy_revision,
                    "target":pending.target,
                }),
            },
            capability,
            input.now,
        )
        .await?;
    let actor = audit::executor(
        &pending.invitation,
        input.request_id,
        "invitation identity notification",
        &serde_json::json!({"kind":"invitation_capability","objectId":input.invitation,
            "deliveryRevision":pending.invitation.delivery_revision,
            "policyRevision":pending.policy_revision}),
    )?;
    notification::queued(tx, &pending.org, &actor, id, message).await
}
