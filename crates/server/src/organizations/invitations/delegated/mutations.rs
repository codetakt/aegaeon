use super::*;

pub(crate) struct Request<'a> {
    pub scope: Scope,
    pub meta: &'a BearerTokenMeta,
    pub actor: &'a AuditActor,
    pub key: &'a str,
    pub runtime: &'a Runtime<'a>,
    pub now: i64,
}

async fn authorized(
    tx: &mut Transaction<'_, Postgres>,
    input: &Request<'_>,
    organization: Uuid,
    roles: &BTreeSet<String>,
) -> Result<(Organization, Authority), RepositoryError> {
    let epoch = epoch::capture(input.scope)?;
    input.actor.validate()?;
    require(matches!(input.actor.kind, ActorKind::Member))?;
    request_key(input.key)?;
    let retained = Retained::capture(input.meta, input.scope, input.now, input.runtime).await?;
    selected::lock_primary_scope(tx, input.scope).await?;
    let org = repo::lock_organization(tx, input.scope, organization).await?;
    let definitions = repo::roles(tx, input.scope).await?;
    require(!roles.is_empty() && roles.len() <= MAX_ROLES)?;
    let versions: BTreeMap<_, _> = roles
        .iter()
        .map(|key| {
            definitions
                .get(key)
                .map(|role| (key.clone(), role.version))
                .ok_or(AuthorityError::Forbidden)
        })
        .collect::<Result<_, _>>()?;
    let temporary = Stored {
        invitation: Invitation {
            id: Uuid::nil(),
            organization_id: organization,
            revision: 1,
            state: State::Pending,
            issued_at: input.now,
            expires_at: cap::invitation_deadline(input.now, None).ok_or(AuthorityError::Invalid)?,
        },
        authority: Authority {
            epoch: Some(epoch),
            delegated: Some(retained),
            team: Uuid::nil(),
            actor: input.actor.clone(),
            grant: Uuid::nil(),
            grant_revision: 0,
            organization_generation: org.grant_generation,
            role_versions: versions,
        },
        recipient: String::new(),
        delivery_revision: 0,
        delivered_at: None,
        hash: None,
        accepted_challenge: None,
        result: None,
    };
    current_with_runtime(tx, input.scope, &temporary, input.now, Some(input.runtime)).await?;
    Ok((org, temporary.authority))
}

pub(crate) async fn issue(
    tx: &mut Transaction<'_, Postgres>,
    input: &Request<'_>,
    value: &FirstAdminRequest,
) -> Result<Invitation, RepositoryError> {
    let (org, authority) = authorized(tx, input, value.organization_id, &value.roles).await?;
    let recipient = recipient_address(&value.recipient)?;
    let digest = digest(
        input,
        &serde_json::json!({"organization":value.organization_id,"expected_revision":value.expected_revision,"recipient":recipient,"roles":value.roles,"lifetime":value.lifetime_seconds.unwrap_or(cap::DEFAULT_INVITATION_SECONDS)}),
    )?;
    if let Some(old) = receipt(tx, input, "invite_member", &digest).await? {
        let stored = load(tx, input.scope, old.id).await?;
        current_with_runtime(tx, input.scope, &stored, input.now, Some(input.runtime)).await?;
        return Ok(stored.invitation);
    }
    if org.revision != value.expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_invitations WHERE environment_id=$1 AND domain_id=$2")
        .bind(input.scope.environment_id).bind(input.scope.domain_id).fetch_one(&mut **tx).await?;
    if count >= MAX_INVITATIONS {
        return Err(AuthorityError::Exhausted.into());
    }
    let expires = cap::invitation_deadline(input.now, value.lifetime_seconds)
        .ok_or(AuthorityError::Invalid)?
        .min(
            authority
                .delegated
                .as_ref()
                .ok_or(AuthorityError::Forbidden)?
                .deadline(),
        );
    require(cap::is_live(
        cap::Purpose::Invitation,
        input.now,
        expires,
        input.now,
    ))?;
    let invitation = Invitation {
        id: Uuid::new_v4(),
        organization_id: org.id,
        revision: 1,
        state: State::Pending,
        issued_at: input.now,
        expires_at: expires,
    };
    let encoded = serde_json::to_value(&authority)?;
    require(serde_json::to_vec(&encoded)?.len() <= 65536)?;
    sqlx::query("INSERT INTO aegaeon.organization_invitations (id,environment_id,domain_id,organization_id,recipient,authority,issued_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(invitation.id).bind(input.scope.environment_id).bind(input.scope.domain_id).bind(org.id).bind(recipient)
        .bind(encoded).bind(input.now).bind(expires).execute(&mut **tx).await?;
    event(
        tx,
        &org,
        input.actor,
        invitation.id,
        invitation.revision,
        "organization.invitation_issued",
    )
    .await?;
    save(tx, input, "invite_member", &digest, &invitation).await?;
    Ok(invitation)
}

pub(crate) async fn inspect(
    tx: &mut Transaction<'_, Postgres>,
    input: &Request<'_>,
    organization: Uuid,
    id: Uuid,
) -> Result<Invitation, RepositoryError> {
    // Hold the scope first; never acquire the original inviter's operator lock.
    selected::lock_primary_scope(tx, input.scope).await?;
    let stored = load_authorized(tx, input.scope, id).await?;
    require(
        stored.invitation.organization_id == organization && stored.authority.delegated.is_some(),
    )?;
    authorized(
        tx,
        input,
        organization,
        &stored.authority.role_versions.keys().cloned().collect(),
    )
    .await?;
    Ok(stored.invitation)
}

pub(crate) async fn revoke(
    tx: &mut Transaction<'_, Postgres>,
    input: &Request<'_>,
    organization: Uuid,
    id: Uuid,
    revision: i64,
) -> Result<Invitation, RepositoryError> {
    let mut value = inspect(tx, input, organization, id).await?;
    let digest = digest(
        input,
        &serde_json::json!({"organization":organization,"id":id,"expected_revision":revision}),
    )?;
    if let Some(old) = receipt(tx, input, "revoke_member_invitation", &digest).await? {
        return Ok(old);
    }
    if value.revision != revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    require(value.state == State::Pending)?;
    value.state = State::Revoked;
    value.revision = super::super::super::model::increment(value.revision, true)?;
    sqlx::query(
        "UPDATE aegaeon.organization_invitations SET state='revoked',revision=$2 WHERE id=$1",
    )
    .bind(id)
    .bind(value.revision)
    .execute(&mut **tx)
    .await?;
    let org = repo::lock_organization(tx, input.scope, organization).await?;
    event(
        tx,
        &org,
        input.actor,
        id,
        value.revision,
        "organization.invitation_revoked",
    )
    .await?;
    save(tx, input, "revoke_member_invitation", &digest, &value).await?;
    Ok(value)
}

fn digest(input: &Request<'_>, body: &serde_json::Value) -> Result<Vec<u8>, RepositoryError> {
    let bytes =
        serde_json::to_vec(&serde_json::json!({"request":body,"reason":input.actor.reason}))?;
    Ok(aegaeon_crypto::hash::sha256_digest(&bytes).to_vec())
}

async fn receipt(
    tx: &mut Transaction<'_, Postgres>,
    input: &Request<'_>,
    operation: &str,
    digest: &[u8],
) -> Result<Option<Invitation>, RepositoryError> {
    let row=sqlx::query("SELECT request_digest,result FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2 AND actor_id=$3 AND actor_kind='member' AND client_id=$4 AND client_registration_id=$5 AND operation=$6 AND idempotency_key=$7")
        .bind(input.scope.environment_id).bind(input.scope.domain_id).bind(input.actor.id).bind(&input.actor.client_id)
        .bind(input.actor.client_registration_id).bind(operation).bind(input.key).fetch_optional(&mut **tx).await?;
    row.map(|row| {
        if row.try_get::<Vec<u8>, _>("request_digest")? != digest {
            return Err(AuthorityError::Conflict.into());
        }
        Ok(serde_json::from_value(row.try_get("result")?)?)
    })
    .transpose()
}

async fn save(
    tx: &mut Transaction<'_, Postgres>,
    input: &Request<'_>,
    operation: &str,
    digest: &[u8],
    value: &Invitation,
) -> Result<(), RepositoryError> {
    // At most one issuance and one terminal cancellation receipt per retained
    // invitation. Issuance and cancellation cannot mint arbitrary extra receipts.
    sqlx::query("INSERT INTO aegaeon.organization_authority_receipts (environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result) VALUES ($1,$2,$3,'member',$4,$5,$6,$7,$8,$9)")
        .bind(input.scope.environment_id).bind(input.scope.domain_id).bind(input.actor.id).bind(&input.actor.client_id)
        .bind(input.actor.client_registration_id).bind(operation).bind(input.key).bind(digest).bind(serde_json::to_value(value)?).execute(&mut **tx).await?;
    Ok(())
}
