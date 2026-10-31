//! Durable attempt transitions. Only the runtime boundary can send a claim.
use super::super::operators::mutations::delivery::{self as configuration, Channel};
use super::*;

pub(crate) struct Claim {
    pub(super) scope: Scope,
    pub(super) invitation: Uuid,
    pub(super) object: Uuid,
    pub(super) challenge: Option<Uuid>,
    pub(super) revision: i64,
    hash: [u8; 32],
    pub(super) claimed_at: i64,
    pub(super) configuration_revision: i64,
    pub(super) channel: Channel,
    pub(super) org: Organization,
    pub(super) actor: AuditActor,
}

impl Claim {
    pub(crate) fn endpoint(&self) -> &str {
        &self.channel.endpoint
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Uncertain,
    Acknowledged,
    Rejected,
}
impl Outcome {
    fn key(self) -> &'static str {
        match self {
            Self::Uncertain => "uncertain",
            Self::Acknowledged => "acknowledged",
            Self::Rejected => "rejected",
        }
    }
}

pub(crate) async fn claim_current(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    invitation: Uuid,
    challenge: Option<Uuid>,
    credential_digest: &str,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Option<(Claim, Delivery)>, RepositoryError> {
    let stored = load(tx, scope, invitation).await?;
    let org = current_with_runtime(tx, scope, &stored, now, runtime).await?;
    let config = configuration::read_locked(tx, scope).await?;
    let channel = config.channel.ok_or(AuthorityError::Forbidden)?;
    require(channel.credential_sha256 == credential_digest)?;
    let object = challenge.unwrap_or(invitation);
    let (revision, at, outcome) = delivery_state(tx, scope, invitation, challenge).await?;
    if matches!(outcome.as_str(), "acknowledged" | "rejected")
        || revision >= MAX_DELIVERIES
        || at.is_some_and(|at| {
            now.checked_sub(at)
                .is_none_or(|age| age < DELIVERY_INTERVAL_SECONDS)
        })
    {
        return Ok(None);
    }
    require(matches!(outcome.as_str(), "unclaimed" | "uncertain"))?;
    let delivery = match challenge {
        Some(id) => {
            delivery::claim_challenge_delivery_current(tx, scope, invitation, id, now, runtime)
                .await?
        }
        None => {
            delivery::claim_invitation_delivery_current(tx, scope, invitation, now, runtime).await?
        }
    };
    Ok(Some((
        Claim {
            scope,
            invitation,
            object,
            challenge,
            revision: revision + 1,
            hash: delivery.hash,
            claimed_at: now,
            configuration_revision: config.revision,
            channel,
            org,
            actor: audit::delivery(&stored, object, revision + 1, now)?,
        },
        delivery,
    )))
}

async fn delivery_state(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    invitation: Uuid,
    challenge: Option<Uuid>,
) -> Result<(i64, Option<i64>, String), RepositoryError> {
    let row=if let Some(id)=challenge {
        sqlx::query("SELECT delivery_revision,delivered_at,delivery_outcome FROM aegaeon.organization_invitation_challenges WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3 AND id=$4 FOR UPDATE")
            .bind(scope.environment_id).bind(scope.domain_id).bind(invitation).bind(id).fetch_optional(&mut **tx).await?
    }else {
        sqlx::query("SELECT delivery_revision,delivered_at,delivery_outcome FROM aegaeon.organization_invitations WHERE environment_id=$1 AND domain_id=$2 AND id=$3 FOR UPDATE")
            .bind(scope.environment_id).bind(scope.domain_id).bind(invitation).fetch_optional(&mut **tx).await?
    }.ok_or(AuthorityError::Forbidden)?;
    Ok((
        row.try_get("delivery_revision")?,
        row.try_get("delivered_at")?,
        row.try_get("delivery_outcome")?,
    ))
}

pub(crate) async fn admit_send_current(
    tx: &mut Transaction<'_, Postgres>,
    claim: &Claim,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<(), RepositoryError> {
    let stored = load(tx, claim.scope, claim.invitation).await?;
    current_with_runtime(tx, claim.scope, &stored, now, runtime).await?;
    require(
        stored.invitation.state == State::Pending
            && now
                .checked_sub(claim.claimed_at)
                .is_some_and(|age| (0..30).contains(&age)),
    )?;
    let config = configuration::read_locked(tx, claim.scope).await?;
    require(
        config.revision == claim.configuration_revision
            && config.channel.as_ref() == Some(&claim.channel),
    )?;
    let (revision, at, outcome) =
        delivery_state(tx, claim.scope, claim.invitation, claim.challenge).await?;
    require(revision == claim.revision && at == Some(claim.claimed_at) && outcome == "uncertain")?;
    require(current_hash(tx, claim).await?.as_deref() == Some(claim.hash.as_slice()))?;
    if let Some(id) = claim.challenge {
        let row=sqlx::query("SELECT recipient_binding,invitation_delivery_revision,issued_at,expires_at FROM aegaeon.organization_invitation_challenges WHERE id=$1")
            .bind(id).fetch_one(&mut **tx).await?;
        let recipient: Recipient = serde_json::from_value(row.try_get("recipient_binding")?)?;
        recipient.check(tx, claim.scope, now).await?;
        require(
            row.try_get::<i64, _>("invitation_delivery_revision")? == stored.delivery_revision
                && cap::is_live(
                    cap::Purpose::RecipientChallenge,
                    row.try_get("issued_at")?,
                    row.try_get("expires_at")?,
                    now,
                ),
        )?;
    }
    Ok(())
}

pub(crate) async fn complete(
    tx: &mut Transaction<'_, Postgres>,
    claim: &Claim,
    outcome: Outcome,
) -> Result<bool, RepositoryError> {
    // Completion records an already admitted attempt, including after revocation.
    // No current inviter decision or mutation to invitation authority is implied.
    let _domain: Uuid = sqlx::query_scalar(
        "SELECT id FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(claim.scope.environment_id)
    .bind(claim.scope.domain_id)
    .fetch_one(&mut **tx)
    .await?;
    let (revision, at, previous) =
        delivery_state(tx, claim.scope, claim.invitation, claim.challenge).await?;
    if revision != claim.revision
        || at != Some(claim.claimed_at)
        || previous != "uncertain"
        || current_hash(tx, claim).await?.as_deref() != Some(claim.hash.as_slice())
    {
        return Ok(false);
    }
    if outcome == Outcome::Uncertain {
        return Ok(true);
    }
    let sql = if claim.challenge.is_some() {
        "UPDATE aegaeon.organization_invitation_challenges SET delivery_outcome=$2 WHERE id=$1"
    } else {
        "UPDATE aegaeon.organization_invitations SET delivery_outcome=$2 WHERE id=$1"
    };
    sqlx::query(sql)
        .bind(claim.object)
        .bind(outcome.key())
        .execute(&mut **tx)
        .await?;
    repo::event(
        tx,
        &claim.org,
        &claim.actor,
        "organization.invitation_transport_result",
        serde_json::json!({"invitation_id":claim.invitation,"object_id":claim.object,
            "delivery_revision":claim.revision,"outcome":outcome,"configurationRevision":claim.configuration_revision,
            "before":{"deliveryRevision":revision,"outcome":previous},"after":{"deliveryRevision":revision,"outcome":outcome}}),
    )
    .await?;
    Ok(true)
}

async fn current_hash(
    tx: &mut Transaction<'_, Postgres>,
    claim: &Claim,
) -> Result<Option<Vec<u8>>, RepositoryError> {
    let sql = if claim.challenge.is_some() {
        "SELECT capability_hash FROM aegaeon.organization_invitation_challenges WHERE id=$1"
    } else {
        "SELECT capability_hash FROM aegaeon.organization_invitations WHERE id=$1"
    };
    Ok(sqlx::query_scalar(sql)
        .bind(claim.object)
        .fetch_one(&mut **tx)
        .await?)
}

#[cfg(test)]
pub(crate) async fn claim(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    invitation: Uuid,
    challenge: Option<Uuid>,
    digest: &str,
    now: i64,
) -> Result<Option<(Claim, Delivery)>, RepositoryError> {
    claim_current(tx, scope, invitation, challenge, digest, now, None).await
}
#[cfg(test)]
pub(crate) async fn admit_send(
    tx: &mut Transaction<'_, Postgres>,
    claim: &Claim,
    now: i64,
) -> Result<(), RepositoryError> {
    admit_send_current(tx, claim, now, None).await
}
