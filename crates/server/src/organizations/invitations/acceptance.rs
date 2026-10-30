use super::*;

pub struct Acceptance<'a> {
    pub request_id: &'a str,
    pub scope: Scope,
    pub invitation_id: Uuid,
    pub invitation_capability: &'a str,
    pub challenge_id: Uuid,
    pub challenge_capability: &'a str,
    pub recipient: &'a Recipient,
    pub now: i64,
}

fn recipient_actor(input: &Acceptance<'_>, stored: &Stored) -> Result<AuditActor, AuthorityError> {
    let actor = AuditActor {
        basis: Some(
            serde_json::json!({"kind":"invitation_recipient","invitationId":stored.invitation.id,"invitationRevision":stored.invitation.revision,"inviterId":stored.authority.actor.id,"inviterKind":stored.authority.actor.kind,"operatorGrantId":(!stored.authority.grant.is_nil()).then_some(stored.authority.grant),"operatorGrantRevision":(stored.authority.grant_revision > 0).then_some(stored.authority.grant_revision),"inviterBasis":stored.authority.actor.basis,"organizationGeneration":stored.authority.organization_generation,"roleVersions":stored.authority.role_versions,"recipientRootId":input.recipient.binding.root_id}),
        ),
        id: input.recipient.binding.user_id,
        kind: ActorKind::Member,
        client_id: input.recipient.binding.client_id.clone(),
        client_registration_id: Some(input.recipient.binding.client_registration_id),
        request_id: input.request_id.to_owned(),
        reason: "invitation recipient confirmation".into(),
    };
    actor.validate()?;
    Ok(actor)
}

pub(crate) async fn request_challenge_current(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    key: &str,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Uuid, RepositoryError> {
    request_key(key)?;
    let stored = load(tx, input.scope, input.invitation_id).await?;
    let org = current_with_runtime(tx, input.scope, &stored, input.now, runtime).await?;
    input.recipient.check(tx, input.scope, input.now).await?;
    let actor = recipient_actor(input, &stored)?;
    require(stored.invitation.state == State::Pending)?;
    require(matches_secret(
        input.scope,
        input.invitation_id,
        stored.delivery_revision,
        cap::Purpose::Invitation,
        stored.hash.as_deref(),
        input.invitation_capability,
    ))?;
    let binding = serde_json::to_value(input.recipient)?;
    let previous = sqlx::query("SELECT id,recipient_binding,invitation_delivery_revision,expires_at FROM aegaeon.organization_invitation_challenges WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3 AND request_key=$4")
        .bind(input.scope.environment_id).bind(input.scope.domain_id).bind(input.invitation_id).bind(key).fetch_optional(&mut **tx).await?;
    if let Some(row) = previous {
        if row.try_get::<serde_json::Value, _>("recipient_binding")? != binding
            || row.try_get::<i64, _>("invitation_delivery_revision")? != stored.delivery_revision
        {
            return Err(AuthorityError::Conflict.into());
        }
        require(input.now < row.try_get::<i64, _>("expires_at")?)?;
        return Ok(row.try_get("id")?);
    }
    if !new_recipient(tx, &org, &stored, input.recipient.binding.user_id).await? {
        return Err(AuthorityError::Forbidden.into());
    }
    let count:i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_invitation_challenges WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3")
        .bind(input.scope.environment_id).bind(input.scope.domain_id).bind(input.invitation_id).fetch_one(&mut **tx).await?;
    if count >= MAX_CHALLENGES {
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
    repo::event(tx, &org, &actor, "organization.recipient_challenge_requested",
        serde_json::json!({"invitation_id":input.invitation_id,"challenge_id":id,"recipient_user_id":input.recipient.binding.user_id,"before":null,"after":{"deliveryRevision":0}})).await?;
    Ok(id)
}

pub(crate) async fn accept_current(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Membership, RepositoryError> {
    let stored = load(tx, input.scope, input.invitation_id).await?;
    let org = current_with_runtime(tx, input.scope, &stored, input.now, runtime).await?;
    input.recipient.check(tx, input.scope, input.now).await?;
    let actor = recipient_actor(input, &stored)?;
    require(matches_secret(
        input.scope,
        input.invitation_id,
        stored.delivery_revision,
        cap::Purpose::Invitation,
        stored.hash.as_deref(),
        input.invitation_capability,
    ))?;
    verify_challenge(tx, input, &stored).await?;
    if stored.invitation.state == State::Accepted {
        require(stored.accepted_challenge == Some(input.challenge_id))?;
        let result = stored.result.ok_or(AuthorityError::Forbidden)?;
        let member = repo::membership(tx, &org, input.recipient.binding.user_id).await?;
        require(member.as_ref() == Some(&result))?;
        return Ok(result);
    }
    if stored.invitation.state != State::Pending
        || !new_recipient(tx, &org, &stored, input.recipient.binding.user_id).await?
    {
        return Err(AuthorityError::Forbidden.into());
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.organization_memberships WHERE environment_id=$1 AND domain_id=$2 LIMIT $3) bounded").bind(input.scope.environment_id).bind(input.scope.domain_id).bind(super::super::commands::capacity::MAX_MEMBERS).fetch_one(&mut **tx).await?;
    if count >= super::super::commands::capacity::MAX_MEMBERS {
        return Err(AuthorityError::Exhausted.into());
    }
    let revision = super::super::model::increment(stored.invitation.revision, false)?;
    let member = repo::update_membership(
        tx,
        input.scope,
        org.id,
        repo::MembershipUpdate {
            user_id: input.recipient.binding.user_id,
            expected_revision: 0,
            state: MembershipState::Active,
            roles: stored.authority.role_versions.keys().cloned().collect(),
        },
        &actor,
    )
    .await?;
    let active = if stored.authority.delegated.is_some() {
        org
    } else {
        repo::transition_organization(
            tx,
            input.scope,
            org.id,
            org.revision,
            OrganizationState::Active,
            &actor,
        )
        .await?
    };
    sqlx::query("UPDATE aegaeon.organization_invitations SET state='accepted',revision=$2,accepted_challenge_id=$3,result=$4 WHERE id=$1")
        .bind(input.invitation_id).bind(revision).bind(input.challenge_id).bind(serde_json::to_value(&member)?).execute(&mut **tx).await?;
    repo::event(tx, &active, &actor, "organization.invitation_accepted",
        serde_json::json!({"invitation_id":input.invitation_id,"revision":revision,"before":{"revision":stored.invitation.revision,"state":stored.invitation.state},"after":{"revision":revision,"state":State::Accepted},
            "recipient_user_id":member.user_id,"incarnation":member.incarnation,"challenge_id":input.challenge_id})).await?;
    Ok(member)
}

async fn verify_challenge(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    stored: &Stored,
) -> Result<(), RepositoryError> {
    let row = sqlx::query("SELECT * FROM aegaeon.organization_invitation_challenges WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3 AND id=$4 FOR UPDATE")
        .bind(input.scope.environment_id).bind(input.scope.domain_id).bind(input.invitation_id).bind(input.challenge_id)
        .fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    require(
        row.try_get::<serde_json::Value, _>("recipient_binding")?
            == serde_json::to_value(input.recipient)?
            && row.try_get::<i64, _>("invitation_delivery_revision")? == stored.delivery_revision,
    )?;
    require(cap::is_live(
        cap::Purpose::RecipientChallenge,
        row.try_get("issued_at")?,
        row.try_get("expires_at")?,
        input.now,
    ))?;
    let hash: Option<Vec<u8>> = row.try_get("capability_hash")?;
    require(matches_secret(
        input.scope,
        input.challenge_id,
        row.try_get("delivery_revision")?,
        cap::Purpose::RecipientChallenge,
        hash.as_deref(),
        input.challenge_capability,
    ))?;
    Ok(())
}

pub async fn request_challenge(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    key: &str,
) -> Result<Uuid, RepositoryError> {
    request_challenge_current(tx, input, key, None).await
}
pub async fn accept_first_admin(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
) -> Result<Membership, RepositoryError> {
    accept_current(tx, input, None).await
}
async fn new_recipient(
    tx: &mut Transaction<'_, Postgres>,
    org: &Organization,
    stored: &Stored,
    user: Uuid,
) -> Result<bool, RepositoryError> {
    if stored.authority.delegated.is_some() {
        Ok(repo::membership(tx, org, user).await?.is_none())
    } else {
        Ok(repo::membership(tx, org, user).await?.is_none()
            && repo::recovery::needs_administrator(tx, org).await?)
    }
}
