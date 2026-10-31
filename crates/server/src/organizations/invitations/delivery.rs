use super::*;

/// Only the configured delivery worker consumes this envelope after commit.
/// Deliberately lacks serialization, cloning and debug formatting.
pub struct Delivery {
    pub recipient: String,
    pub object_id: Uuid,
    pub purpose: cap::Purpose,
    pub capability: cap::Capability,
    pub expires_at: i64,
    pub(crate) hash: [u8; 32],
}

pub(super) fn next_attempt(
    revision: i64,
    delivered_at: Option<i64>,
    now: i64,
) -> Result<i64, AuthorityError> {
    require(revision >= 0 && now >= 0)?;
    if revision >= MAX_DELIVERIES {
        return Err(AuthorityError::Exhausted);
    }
    if delivered_at.is_some_and(|last| {
        now.checked_sub(last)
            .is_none_or(|elapsed| elapsed < DELIVERY_INTERVAL_SECONDS)
    }) {
        return Err(AuthorityError::Forbidden);
    }
    Ok(revision + 1)
}

pub(super) fn generate(
    scope: Scope,
    id: Uuid,
    revision: i64,
    purpose: cap::Purpose,
) -> Result<(cap::Capability, [u8; 32]), RepositoryError> {
    cap::generate(cap::Binding {
        scope,
        object_id: id,
        delivery_revision: revision,
        purpose,
    })
    .map_err(|_| sqlx::Error::Protocol("invitation capability supplier unavailable".into()).into())
}

pub(crate) async fn claim_invitation_delivery_current(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: Uuid,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Delivery, RepositoryError> {
    let stored = load(tx, scope, id).await?;
    let org = current_with_runtime(tx, scope, &stored, now, runtime).await?;
    require(stored.invitation.state == State::Pending)?;
    let revision = next_attempt(stored.delivery_revision, stored.delivered_at, now)?;
    let version = super::super::model::increment(stored.invitation.revision, false)?;
    let (capability, hash) = generate(scope, id, revision, cap::Purpose::Invitation)?;
    sqlx::query("UPDATE aegaeon.organization_invitations SET delivery_revision=$2,delivered_at=$3,capability_hash=$4,revision=$5,delivery_outcome='uncertain' WHERE id=$1")
        .bind(id).bind(revision).bind(now).bind(hash.as_slice()).bind(version).execute(&mut **tx).await?;
    let actor = audit::delivery(&stored, id, revision, now)?;
    repo::event(tx,&org,&actor,"organization.invitation_delivery_claimed",
        serde_json::json!({"invitation_id":id,"revision":version,"delivery_revision":revision,
            "before":{"revision":stored.invitation.revision,"deliveryRevision":stored.delivery_revision},
            "after":{"revision":version,"deliveryRevision":revision}})).await?;
    Ok(Delivery {
        hash,
        recipient: stored.recipient,
        object_id: id,
        purpose: cap::Purpose::Invitation,
        capability,
        expires_at: stored.invitation.expires_at,
    })
}

pub(crate) async fn claim_challenge_delivery_current(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    invitation: Uuid,
    challenge: Uuid,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Delivery, RepositoryError> {
    let stored = load(tx, scope, invitation).await?;
    let org = current_with_runtime(tx, scope, &stored, now, runtime).await?;
    require(stored.invitation.state == State::Pending)?;
    let row = sqlx::query("SELECT * FROM aegaeon.organization_invitation_challenges WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3 AND id=$4 FOR UPDATE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(invitation).bind(challenge)
        .fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let recipient: Recipient = serde_json::from_value(row.try_get("recipient_binding")?)?;
    recipient.check(tx, scope, now).await?;
    require(row.try_get::<i64, _>("invitation_delivery_revision")? == stored.delivery_revision)?;
    let expires: i64 = row.try_get("expires_at")?;
    require(cap::is_live(
        cap::Purpose::RecipientChallenge,
        row.try_get("issued_at")?,
        expires,
        now,
    ))?;
    let revision = next_attempt(
        row.try_get("delivery_revision")?,
        row.try_get("delivered_at")?,
        now,
    )?;
    let (capability, hash) =
        generate(scope, challenge, revision, cap::Purpose::RecipientChallenge)?;
    sqlx::query("UPDATE aegaeon.organization_invitation_challenges SET delivery_revision=$2,delivered_at=$3,capability_hash=$4,delivery_outcome='uncertain' WHERE id=$1")
        .bind(challenge).bind(revision).bind(now).bind(hash.as_slice()).execute(&mut **tx).await?;
    let actor = audit::delivery(&stored, challenge, revision, now)?;
    repo::event(tx, &org, &actor, "organization.recipient_delivery_claimed",
        serde_json::json!({"invitation_id":invitation,"challenge_id":challenge,"delivery_revision":revision,
            "before":{"deliveryRevision":row.try_get::<i64,_>("delivery_revision")?},"after":{"deliveryRevision":revision}})).await?;
    Ok(Delivery {
        hash,
        recipient: stored.recipient,
        object_id: challenge,
        purpose: cap::Purpose::RecipientChallenge,
        capability,
        expires_at: expires,
    })
}

pub async fn claim_invitation_delivery(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: Uuid,
    now: i64,
) -> Result<Delivery, RepositoryError> {
    claim_invitation_delivery_current(tx, scope, id, now, None).await
}
pub async fn claim_challenge_delivery(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    invitation: Uuid,
    challenge: Uuid,
    now: i64,
) -> Result<Delivery, RepositoryError> {
    claim_challenge_delivery_current(tx, scope, invitation, challenge, now, None).await
}
