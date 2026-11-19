//! An explicit selected-runtime command, separate from transport retries.
//! Possession of the current private delivery credential authorizes this service
//! action; it cannot create authority beyond the original, still-current purpose.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Reissue {
    pub scope: Scope,
    pub invitation: Uuid,
    pub challenge: Option<Uuid>,
    pub identity_request: Option<Uuid>,
    pub expected_delivery_revision: i64,
    pub operation: Uuid,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Reissued {
    pub message_id: Uuid,
    pub delivery_revision: i64,
    pub expires_at: i64,
}

pub(crate) async fn reissue(
    tx: &mut Transaction<'_, Postgres>,
    input: &Reissue,
    credential_digest: &str,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Reissued, RepositoryError> {
    validate(input)?;
    let object = input
        .challenge
        .or(input.identity_request)
        .unwrap_or(input.invitation);
    let mut state = if let Some(id) = input.challenge {
        admission::challenge_state(tx, input.scope, input.invitation, id, now, runtime).await?
    } else if let Some(id) = input.identity_request {
        enrollment::durable::current_for_send(tx, input.scope, input.invitation, id, now, runtime)
            .await?
    } else {
        admission::invitation_state(tx, input.scope, input.invitation, now, runtime).await?
    };
    let producer = Producer::current(tx, input.scope)
        .await?
        .ok_or(AuthorityError::Forbidden)?;
    require(producer.channel.credential_sha256 == credential_digest)?;
    let actor = audit::executor(
        &state.invitation,
        &input.operation.to_string(),
        "explicit notification reissue",
        &serde_json::json!({"kind":"service","service":"notification_reissue",
            "objectId":object,"expectedDeliveryRevision":input.expected_delivery_revision}),
    )?;
    let digest = sha256_digest(&serde_json::to_vec(&serde_json::json!({
        "request":input,"generation":producer.selection.generation(),
        "deployment":producer.selection.deployment_id(),
    }))?);
    if let Some(receipt) = receipt(tx, input, &digest).await? {
        return Ok(receipt);
    }
    if state.revision != input.expected_delivery_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    let (capability, hash, revision) = rotate_proof(tx, input, &mut state, object, now).await?;
    let predecessor = outbox::supersede(
        tx,
        input.scope.environment_id,
        template(state.purpose),
        object,
        now,
    )
    .await?;
    let message = producer
        .enqueue(
            tx,
            Proof {
                scope: input.scope,
                invitation: &state.invitation,
                object_id: object,
                revision,
                purpose: state.purpose,
                expires_at: state.expires_at,
                hash: &hash,
                purpose_binding: state.purpose_binding,
            },
            capability,
            now,
        )
        .await?;
    let org = repo::lock_organization(tx, input.scope, state.invitation.invitation.organization_id)
        .await?;
    repo::event(
        tx,
        &org,
        &actor,
        "organization.notification_reissued",
        serde_json::json!({"object_id":object,"predecessor_message_id":predecessor,
            "message_id":message,"before":{"deliveryRevision":input.expected_delivery_revision},
            "after":{"deliveryRevision":revision},"expiresAt":state.expires_at}),
    )
    .await?;
    let value = Reissued {
        message_id: message,
        delivery_revision: revision,
        expires_at: state.expires_at,
    };
    save(tx, input, &actor, &digest, &value).await?;
    Ok(value)
}

fn validate(input: &Reissue) -> Result<(), RepositoryError> {
    require(
        !input.invitation.is_nil()
            && !input.operation.is_nil()
            && input
                .challenge
                .is_none_or(|id| !id.is_nil() && id != input.invitation)
            && input
                .identity_request
                .is_none_or(|id| !id.is_nil() && id != input.invitation)
            && !(input.challenge.is_some() && input.identity_request.is_some())
            && (0..MAX_DELIVERIES).contains(&input.expected_delivery_revision),
    )?;
    Ok(())
}

async fn rotate_proof(
    tx: &mut Transaction<'_, Postgres>,
    input: &Reissue,
    state: &mut CurrentProof,
    object: Uuid,
    now: i64,
) -> Result<(cap::Capability, [u8; 32], i64), RepositoryError> {
    let revision = delivery::next_attempt(state.revision, state.delivered_at, now)?;
    let (capability, hash) = delivery::generate(input.scope, object, revision, state.purpose)?;
    // The fixed statement is selected by the checked purpose, never by input SQL.
    let query = match state.purpose {
        cap::Purpose::Invitation =>
            "UPDATE aegaeon.organization_invitations SET delivery_revision=$2,delivered_at=$3,capability_hash=$4,delivery_outcome='uncertain',revision=revision+1 WHERE id=$1",
        cap::Purpose::RecipientChallenge =>
            "UPDATE aegaeon.organization_invitation_challenges SET delivery_revision=$2,delivered_at=$3,capability_hash=$4,delivery_outcome='uncertain' WHERE id=$1",
        cap::Purpose::IdentityRegistration | cap::Purpose::IdentityRecovery =>
            "UPDATE aegaeon.organization_identity_requests SET delivery_revision=$2,delivered_at=$3,capability_hash=$4,delivery_outcome='uncertain' WHERE id=$1",
    };
    if matches!(state.purpose, cap::Purpose::Invitation) {
        // Preserve the terminal-revocation revision reserve.
        state.invitation.invitation.revision =
            super::super::super::model::increment(state.invitation.invitation.revision, false)?;
        state.invitation.delivery_revision = revision;
    }
    let changed = sqlx::query(query)
        .bind(object)
        .bind(revision)
        .bind(now)
        .bind(hash.as_slice())
        .execute(&mut **tx)
        .await?;
    require(changed.rows_affected() == 1)?;
    Ok((capability, hash, revision))
}

fn actor_kind(actor: &AuditActor) -> &'static str {
    match actor.kind {
        ActorKind::Operator => "operator",
        ActorKind::Member => "member",
    }
}

async fn receipt(
    tx: &mut Transaction<'_, Postgres>,
    input: &Reissue,
    digest: &[u8],
) -> Result<Option<Reissued>, RepositoryError> {
    // Serialize this service operation before changing a proof. A hash collision
    // only serializes unrelated commands; the exact Environment/UUID predicate
    // and partial unique index independently enforce operation identity.
    let namespace = sha256_digest(&serde_json::to_vec(&serde_json::json!({
        "namespace":"notification_reissue_v1","environment":input.scope.environment_id,
        "operation":input.operation,
    }))?);
    let mut key = [0; 8];
    key.copy_from_slice(&namespace[..8]);
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock($1)")
        .bind(i64::from_be_bytes(key))
        .execute(&mut **tx)
        .await?;
    let row = sqlx::query("SELECT request_digest,result FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND operation='notification_reissue' AND idempotency_key=$2")
        .bind(input.scope.environment_id).bind(input.operation.to_string())
        .fetch_optional(&mut **tx).await?;
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
    input: &Reissue,
    actor: &AuditActor,
    digest: &[u8],
    value: &Reissued,
) -> Result<(), RepositoryError> {
    // The owning object's finite proof revision bounds these permanent receipts.
    // Queue transport GC never removes authorization/idempotency receipts.
    sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result) VALUES ($1,$2,$3,$4,$5,$6,'notification_reissue',$7,$8,$9)")
        .bind(input.scope.environment_id).bind(input.scope.domain_id).bind(actor.id)
        .bind(actor_kind(actor)).bind(&actor.client_id).bind(actor.client_registration_id.unwrap_or(Uuid::nil()))
        .bind(input.operation.to_string()).bind(digest).bind(serde_json::to_value(value)?)
        .execute(&mut **tx).await?;
    Ok(())
}
