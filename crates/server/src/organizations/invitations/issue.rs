use super::*;

#[derive(Serialize)]
pub struct FirstAdminRequest {
    pub organization_id: Uuid,
    pub expected_revision: i64,
    pub recipient: String,
    pub roles: BTreeSet<String>,
    pub lifetime_seconds: Option<i64>,
}

pub struct Issuance<'a> {
    pub scope: Scope,
    pub team: Uuid,
    pub actor: &'a AuditActor,
    pub key: &'a str,
    pub request: &'a FirstAdminRequest,
    pub now: i64,
}

pub async fn issue_first_admin(
    tx: &mut Transaction<'_, Postgres>,
    input: Issuance<'_>,
) -> Result<Invitation, RepositoryError> {
    let Issuance {
        scope,
        team,
        actor,
        key,
        request,
        now,
    } = input;
    let epoch = epoch::capture(scope)?;
    actor.validate()?;
    request_key(key)?;
    require(matches!(actor.kind, ActorKind::Operator))?;
    let grant = operators::lock_operator_authority(
        tx,
        scope,
        team,
        actor.id,
        operators::Capability::Provision,
    )
    .await?;
    let recipient = recipient_address(&request.recipient)?;
    let digest = aegaeon_crypto::hash::sha256_digest(&serde_json::to_vec(
        &serde_json::json!({"organization":request.organization_id,"expected_revision":request.expected_revision,"recipient":recipient,"roles":request.roles,"lifetime":request.lifetime_seconds.unwrap_or(cap::DEFAULT_INVITATION_SECONDS),"reason":actor.reason}),
    )?);
    if let Some(previous) =
        receipt(tx, scope, actor, "invite_first_admin", key, digest.as_ref()).await?
    {
        let stored = load(tx, scope, previous.id).await?;
        current(tx, scope, &stored, now).await?;
        return Ok(stored.invitation);
    }
    let audited_actor = actor.with_operator(&grant, operators::Capability::Provision);
    let actor = &audited_actor;
    let org = repo::lock_organization(tx, scope, request.organization_id).await?;
    if org.revision != request.expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    require(org.state == OrganizationState::Provisioning)?;
    require(repo::recovery::needs_administrator(tx, &org).await?)?;
    let role_versions = role_ceiling(tx, scope, &request.roles).await?;
    let count:i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_invitations WHERE environment_id=$1 AND domain_id=$2")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_one(&mut **tx).await?;
    if count >= MAX_INVITATIONS {
        return Err(AuthorityError::Exhausted.into());
    }
    let value = Invitation {
        id: Uuid::new_v4(),
        organization_id: org.id,
        revision: 1,
        state: State::Pending,
        issued_at: now,
        expires_at: cap::invitation_deadline(now, request.lifetime_seconds)
            .ok_or(AuthorityError::Invalid)?,
    };
    let authority = Authority {
        epoch: Some(epoch),
        delegated: None,
        team,
        actor: actor.clone(),
        grant: grant.grant(),
        grant_revision: grant.revision(),
        organization_generation: org.grant_generation,
        role_versions,
    };
    sqlx::query("INSERT INTO aegaeon.organization_invitations (id,environment_id,domain_id,organization_id,recipient,authority,issued_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(value.id).bind(scope.environment_id).bind(scope.domain_id).bind(org.id).bind(recipient)
        .bind(serde_json::to_value(authority)?).bind(now).bind(value.expires_at).execute(&mut **tx).await?;
    event(
        tx,
        &org,
        actor,
        value.id,
        value.revision,
        "organization.invitation_issued",
    )
    .await?;
    save_receipt(
        tx,
        scope,
        actor,
        "invite_first_admin",
        key,
        digest.as_ref(),
        &value,
    )
    .await?;
    Ok(value)
}

async fn receipt(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    actor: &AuditActor,
    operation: &str,
    key: &str,
    digest: &[u8],
) -> Result<Option<Invitation>, RepositoryError> {
    let row = sqlx::query("SELECT request_digest,result FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2 AND actor_id=$3 AND actor_kind='operator' AND client_id=$4 AND operation=$5 AND idempotency_key=$6 AND client_registration_id=$7")
        .bind(scope.environment_id).bind(scope.domain_id).bind(actor.id).bind(&actor.client_id)
        .bind(operation).bind(key).bind(Uuid::nil()).fetch_optional(&mut **tx).await?;
    row.map(|r| {
        if r.try_get::<Vec<u8>, _>("request_digest")? != digest {
            return Err(AuthorityError::Conflict.into());
        }
        Ok(serde_json::from_value(r.try_get("result")?)?)
    })
    .transpose()
}

async fn save_receipt(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    actor: &AuditActor,
    operation: &str,
    key: &str,
    digest: &[u8],
    value: &Invitation,
) -> Result<(), RepositoryError> {
    sqlx::query("INSERT INTO aegaeon.organization_authority_receipts (environment_id,domain_id,actor_id,actor_kind,client_id,operation,idempotency_key,request_digest,result,client_registration_id) VALUES ($1,$2,$3,'operator',$4,$5,$6,$7,$8,$9)")
        .bind(scope.environment_id).bind(scope.domain_id).bind(actor.id).bind(&actor.client_id)
        .bind(operation).bind(key).bind(digest).bind(serde_json::to_value(value)?).bind(Uuid::nil()).execute(&mut **tx).await?;
    Ok(())
}

pub struct Revocation<'a> {
    pub scope: Scope,
    pub team: Uuid,
    pub actor: &'a AuditActor,
    pub key: &'a str,
    pub id: Uuid,
    pub expected_revision: i64,
}

/// Terminal cancellation is independent of issuance capacity and expiry.
pub async fn revoke(
    tx: &mut Transaction<'_, Postgres>,
    input: Revocation<'_>,
) -> Result<Invitation, RepositoryError> {
    input.actor.validate()?;
    request_key(input.key)?;
    require(matches!(input.actor.kind, ActorKind::Operator))?;
    let authority = operators::lock_operator_authority(
        tx,
        input.scope,
        input.team,
        input.actor.id,
        operators::Capability::Provision,
    )
    .await?;
    let audited_actor = input
        .actor
        .with_operator(&authority, operators::Capability::Provision);
    let input = Revocation {
        actor: &audited_actor,
        ..input
    };
    let digest = aegaeon_crypto::hash::sha256_digest(&serde_json::to_vec(&serde_json::json!({
        "id":input.id,"expected_revision":input.expected_revision,"reason":input.actor.reason}))?);
    if let Some(value) = receipt(
        tx,
        input.scope,
        input.actor,
        "revoke_invitation",
        input.key,
        digest.as_ref(),
    )
    .await?
    {
        return Ok(value);
    }
    let mut stored = load_authorized(tx, input.scope, input.id).await?;
    if stored.invitation.revision != input.expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    require(stored.invitation.state == State::Pending)?;
    let org = repo::lock_organization(tx, input.scope, stored.invitation.organization_id).await?;
    stored.invitation.revision = super::super::model::increment(stored.invitation.revision, true)?;
    stored.invitation.state = State::Revoked;
    sqlx::query(
        "UPDATE aegaeon.organization_invitations SET state='revoked',revision=$2 WHERE id=$1",
    )
    .bind(input.id)
    .bind(stored.invitation.revision)
    .execute(&mut **tx)
    .await?;
    event(
        tx,
        &org,
        input.actor,
        input.id,
        stored.invitation.revision,
        "organization.invitation_revoked",
    )
    .await?;
    save_receipt(
        tx,
        input.scope,
        input.actor,
        "revoke_invitation",
        input.key,
        digest.as_ref(),
        &stored.invitation,
    )
    .await?;
    Ok(stored.invitation)
}

async fn role_ceiling(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    roles: &BTreeSet<String>,
) -> Result<BTreeMap<String, i64>, RepositoryError> {
    let definitions = repo::roles(tx, scope).await?;
    require(!roles.is_empty() && roles.len() <= MAX_ROLES)?;
    let role_versions = roles
        .iter()
        .map(|key| {
            definitions
                .get(key)
                .map(|r| (key.clone(), r.version))
                .ok_or(AuthorityError::Forbidden)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    require(
        roles
            .iter()
            .any(|key| definitions.get(key).is_some_and(|r| r.manages_members)),
    )?;
    Ok(role_versions)
}
