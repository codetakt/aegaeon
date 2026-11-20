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

pub(super) fn recipient_actor(
    input: &Acceptance<'_>,
    stored: &Stored,
) -> Result<AuditActor, AuthorityError> {
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

pub(super) struct Verified {
    pub org: Organization,
    pub stored: Stored,
    pub challenge_revision: i64,
    pub expires_at: i64,
}

pub(super) async fn verified(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Verified, RepositoryError> {
    let stored = load(tx, input.scope, input.invitation_id).await?;
    let org = current_with_runtime(tx, input.scope, &stored, input.now, runtime).await?;
    input.recipient.check(tx, input.scope, input.now).await?;
    if !matches_secret(
        input.scope,
        input.invitation_id,
        stored.delivery_revision,
        cap::Purpose::Invitation,
        stored.hash.as_deref(),
        input.invitation_capability,
    ) || stored
        .authority
        .hosted_client_registration_id
        .is_some_and(|id| id != input.recipient.binding.client_registration_id)
    {
        return Err(AuthorityError::Forbidden.into());
    }
    let (challenge_revision, expires_at) = verify_challenge(tx, input, &stored).await?;
    match stored.invitation.state {
        State::Accepted => {
            let receipt = stored.result.as_ref().ok_or(AuthorityError::Forbidden)?;
            let member = repo::membership(tx, &org, input.recipient.binding.user_id).await?;
            if stored.accepted_challenge != Some(input.challenge_id)
                || !receipt.valid()
                || (stored.authority.hosted_client_registration_id.is_some()
                    && receipt.validator().is_none())
                || member.as_ref() != Some(receipt.membership())
            {
                return Err(AuthorityError::Forbidden.into());
            }
        }
        State::Pending
            if stored.result.is_none()
                && stored.accepted_challenge.is_none()
                && new_recipient(tx, &org, &stored, input.recipient.binding.user_id).await? => {}
        _ => return Err(AuthorityError::Forbidden.into()),
    }
    Ok(Verified {
        org,
        stored,
        challenge_revision,
        expires_at,
    })
}

pub(crate) async fn accept_conditional(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    runtime: Option<&delegated::Runtime<'_>>,
    condition: &preview::Condition,
) -> Result<(Membership, i64), preview::Error> {
    let Verified {
        org,
        stored,
        challenge_revision,
        expires_at,
    } = verified(tx, input, runtime).await?;
    let required = stored.authority.hosted_client_registration_id.is_some();
    if stored.invitation.state == State::Accepted {
        let receipt = stored
            .result
            .as_ref()
            .ok_or(RepositoryError::from(AuthorityError::Forbidden))?;
        let tag = condition.tag(required || receipt.validator().is_some())?;
        if receipt.validator().map(str::as_bytes) != tag {
            return Err(RepositoryError::from(AuthorityError::PreconditionFailed).into());
        }
        return Ok((receipt.membership().clone(), expires_at));
    }
    let tag = match condition.tag(required)? {
        None => None,
        Some(presented) => {
            let (_, current) =
                preview::validated(tx, input, &org, &stored, challenge_revision).await?;
            if current.as_bytes() != presented {
                return Err(RepositoryError::from(AuthorityError::PreconditionFailed).into());
            }
            Some(current)
        }
    };
    let member = commit(tx, input, org, &stored, tag).await?;
    Ok((member, expires_at))
}

async fn commit(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    org: Organization,
    stored: &Stored,
    tag: Option<String>,
) -> Result<Membership, RepositoryError> {
    let actor = recipient_actor(input, stored)?;
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
    let result = match tag {
        Some(validator) => serde_json::to_value(preview::Receipt::Conditional {
            membership: member.clone(),
            validator,
        })?,
        None => serde_json::to_value(&member)?,
    };
    sqlx::query("UPDATE aegaeon.organization_invitations SET state='accepted',revision=$2,accepted_challenge_id=$3,result=$4 WHERE id=$1")
        .bind(input.invitation_id).bind(revision).bind(input.challenge_id).bind(result).execute(&mut **tx).await?;
    repo::event(tx, &active, &actor, "organization.invitation_accepted",
        serde_json::json!({"invitation_id":input.invitation_id,"revision":revision,"before":{"revision":stored.invitation.revision,"state":stored.invitation.state},"after":{"revision":revision,"state":State::Accepted},
            "recipient_user_id":member.user_id,"incarnation":member.incarnation,"challenge_id":input.challenge_id})).await?;
    Ok(member)
}

async fn verify_challenge(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    stored: &Stored,
) -> Result<(i64, i64), RepositoryError> {
    let row = sqlx::query("SELECT * FROM aegaeon.organization_invitation_challenges WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3 AND id=$4 FOR UPDATE")
        .bind(input.scope.environment_id).bind(input.scope.domain_id).bind(input.invitation_id).bind(input.challenge_id)
        .fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    if row.try_get::<serde_json::Value, _>("recipient_binding")?
        != serde_json::to_value(input.recipient)?
        || row.try_get::<i64, _>("invitation_delivery_revision")? != stored.delivery_revision
        || !cap::is_live(
            cap::Purpose::RecipientChallenge,
            row.try_get("issued_at")?,
            row.try_get("expires_at")?,
            input.now,
        )
    {
        return Err(AuthorityError::Forbidden.into());
    }
    let hash: Option<Vec<u8>> = row.try_get("capability_hash")?;
    if !matches_secret(
        input.scope,
        input.challenge_id,
        row.try_get("delivery_revision")?,
        cap::Purpose::RecipientChallenge,
        hash.as_deref(),
        input.challenge_capability,
    ) {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok((
        row.try_get("delivery_revision")?,
        row.try_get("expires_at")?,
    ))
}

pub async fn accept_first_admin(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
) -> Result<Membership, RepositoryError> {
    accept_conditional(tx, input, None, &preview::Condition::Missing)
        .await
        .map(|(member, _)| member)
        .map_err(|err| match err {
            preview::Error::Storage(e) => e,
            _ => AuthorityError::Forbidden.into(),
        })
}
pub(super) async fn new_recipient(
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
