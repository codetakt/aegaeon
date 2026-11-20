use super::{acceptance::new_recipient, acceptance::recipient_actor, *};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct ChallengeStatus {
    pub invitation_expires_at: i64,
    pub remaining_challenges: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct AllocatedChallenge {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub challenge_id: Uuid,
    pub expires_at: i64,
    pub remaining_challenges: i64,
}

async fn current_invitation(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<(Stored, Organization), RepositoryError> {
    let stored = load(tx, input.scope, input.invitation_id).await?;
    if stored
        .authority
        .hosted_client_registration_id
        .is_some_and(|id| id != input.recipient.binding.client_registration_id)
    {
        return Err(AuthorityError::Forbidden.into());
    }
    let org = current_with_runtime(tx, input.scope, &stored, input.now, runtime).await?;
    input.recipient.check(tx, input.scope, input.now).await?;
    Ok((stored, org))
}

fn pending_with_proof(stored: &Stored, input: &Acceptance<'_>) -> bool {
    stored.invitation.state == State::Pending
        && matches_secret(
            input.scope,
            input.invitation_id,
            stored.delivery_revision,
            cap::Purpose::Invitation,
            stored.hash.as_deref(),
            input.invitation_capability,
        )
}

// Callers hold the invitation lock, shared with all new allocations.
async fn remaining(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
) -> Result<i64, RepositoryError> {
    let allocated: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.organization_invitation_challenges
         WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3",
    )
    .bind(input.scope.environment_id)
    .bind(input.scope.domain_id)
    .bind(input.invitation_id)
    .fetch_one(&mut **tx)
    .await?;
    require(allocated <= MAX_CHALLENGES)?;
    Ok(MAX_CHALLENGES - allocated)
}

pub(crate) async fn challenge_status(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    runtime: &delegated::Runtime<'_>,
) -> Result<ChallengeStatus, RepositoryError> {
    let (stored, org) = current_invitation(tx, input, Some(runtime)).await?;
    if !pending_with_proof(&stored, input)
        || !new_recipient(tx, &org, &stored, input.recipient.binding.user_id).await?
    {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(ChallengeStatus {
        invitation_expires_at: stored.invitation.expires_at,
        remaining_challenges: remaining(tx, input).await?,
    })
}

pub(crate) async fn request_challenge_current(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    key: &str,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<AllocatedChallenge, RepositoryError> {
    request_key(key)?;
    let (stored, org) = current_invitation(tx, input, runtime).await?;
    require(pending_with_proof(&stored, input))?;
    let actor = recipient_actor(input, &stored)?;
    let binding = serde_json::to_value(input.recipient)?;
    let previous = sqlx::query("SELECT id,recipient_binding,invitation_delivery_revision,expires_at FROM aegaeon.organization_invitation_challenges WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3 AND request_key=$4")
        .bind(input.scope.environment_id).bind(input.scope.domain_id).bind(input.invitation_id).bind(key).fetch_optional(&mut **tx).await?;
    if let Some(row) = previous {
        if row.try_get::<serde_json::Value, _>("recipient_binding")? != binding
            || row.try_get::<i64, _>("invitation_delivery_revision")? != stored.delivery_revision
        {
            return Err(AuthorityError::Conflict.into());
        }
        let expires_at = row.try_get("expires_at")?;
        require(input.now < expires_at)?;
        return Ok(AllocatedChallenge {
            challenge_id: row.try_get("id")?,
            expires_at,
            remaining_challenges: remaining(tx, input).await?,
        });
    }
    if !new_recipient(tx, &org, &stored, input.recipient.binding.user_id).await? {
        return Err(AuthorityError::Forbidden.into());
    }
    preview::check_hosted_display(tx, &org, &stored.authority).await?;
    let available = remaining(tx, input).await?;
    if available == 0 {
        return Err(AuthorityError::Exhausted.into());
    }
    let expires = cap::challenge_deadline(input.now)
        .ok_or(AuthorityError::Exhausted)?
        .min(stored.invitation.expires_at)
        .min(input.recipient.expires_at);
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.organization_invitation_challenges (id,environment_id,domain_id,invitation_id,invitation_delivery_revision,recipient_binding,request_key,issued_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(id).bind(input.scope.environment_id).bind(input.scope.domain_id).bind(input.invitation_id)
        .bind(stored.delivery_revision).bind(binding).bind(key).bind(input.now).bind(expires).execute(&mut **tx).await?;
    let queued = durable::enqueue_challenge(tx, input, &stored, &org, id, expires).await?;
    repo::event(tx, &org, &actor, "organization.recipient_challenge_requested",
        serde_json::json!({"invitation_id":input.invitation_id,"challenge_id":id,"recipient_user_id":input.recipient.binding.user_id,"before":null,"after":{"deliveryRevision":i64::from(queued)}})).await?;
    Ok(AllocatedChallenge {
        challenge_id: id,
        expires_at: expires,
        remaining_challenges: available - 1,
    })
}

pub async fn request_challenge(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    key: &str,
) -> Result<Uuid, RepositoryError> {
    Ok(request_challenge_current(tx, input, key, None)
        .await?
        .challenge_id)
}
