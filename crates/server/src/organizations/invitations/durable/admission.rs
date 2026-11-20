//! Reconstruct purpose authority from current locked rows before opening mail.
use super::*;
use crate::organizations::notification_envelope::PrivateKeyRing;

pub(crate) struct Authorized {
    pub context: MessageContext,
    pub endpoint: String,
    key_version: String,
    ciphertext: String,
    scope: Scope,
    invitation: Uuid,
    object: Uuid,
    purpose: cap::Purpose,
    revision: i64,
    hash: [u8; 32],
    recipient: String,
    issuer: String,
    admitted_at: i64,
    pub lease_until: i64,
}

impl Authorized {
    /// The runtime caller must first confirm the admission transaction committed.
    /// Parse borrowed payload data and verify its proof against current SQL state.
    pub(crate) fn open(
        &self,
        ring: &PrivateKeyRing,
        now: i64,
    ) -> Result<Zeroizing<Vec<u8>>, RepositoryError> {
        require(now >= self.admitted_at && now < self.lease_until)?;
        let plaintext = ring
            .open(&self.key_version, &self.context, &self.ciphertext, now)
            .map_err(|_| RepositoryError::Unavailable)?;
        let payload: Payload<'_> =
            serde_json::from_slice(&plaintext).map_err(|_| AuthorityError::Forbidden)?;
        require(
            payload.version == 2
                && payload.message_id == self.context.message_id
                && payload.template == self.context.template
                && payload.recipient == self.recipient
                && payload.issuer == self.issuer
                && payload.environment_id == self.scope.environment_id
                && payload.domain_id == self.scope.domain_id
                && payload.invitation_id == self.invitation
                && payload.object_id == self.object
                && payload.delivery_revision == self.revision
                && payload.expires_at == self.context.expires_at
                && cap::matches(
                    cap::Binding {
                        scope: self.scope,
                        object_id: self.object,
                        delivery_revision: self.revision,
                        purpose: self.purpose,
                    },
                    &self.hash,
                    payload.capability,
                ),
        )?;
        Ok(plaintext)
    }
}

pub(crate) async fn admit_current(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    claim: &outbox::Claim,
    selection: Selection,
    credential_digest: &str,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Authorized, RepositoryError> {
    require(
        scope.environment_id == claim.environment_id && Some(scope.domain_id) == claim.domain_id,
    )?;
    let invitation = claim.parent_id.unwrap_or(claim.object_id);
    let state = match claim.purpose.as_str() {
        "organization_invitation" => {
            require(claim.parent_id.is_none())?;
            invitation_state(tx, scope, invitation, now, runtime).await?
        }
        "organization_recipient_challenge" => {
            require(claim.parent_id.is_some_and(|id| id != claim.object_id))?;
            challenge_state(tx, scope, invitation, claim.object_id, now, runtime).await?
        }
        "organization_identity_registration" | "organization_identity_recovery" => {
            require(claim.parent_id.is_some_and(|id| id != claim.object_id))?;
            enrollment::durable::current_for_send(
                tx,
                scope,
                invitation,
                claim.object_id,
                now,
                runtime,
            )
            .await?
        }
        _ => return Err(AuthorityError::Forbidden.into()),
    };
    require(
        claim.purpose == template(state.purpose)
            && claim.expires_at == state.expires_at
            && state.revision > 0
            && state.hash.len() == 32,
    )?;
    let producer = Producer::current(tx, scope, &state.invitation)
        .await?
        .ok_or(AuthorityError::Forbidden)?;
    require(
        producer.selection == selection && producer.channel.credential_sha256 == credential_digest,
    )?;
    // Only the immutable payload digest is an issuance fact read from the
    // outbox. No authority, destination, purpose, revision or generation is
    // adopted from a decoded envelope or its stored context.
    let digest: serde_json::Value = sqlx::query_scalar("SELECT context->'payload_digest' FROM aegaeon.notification_messages WHERE environment_id=$1 AND id=$2")
        .bind(scope.environment_id).bind(claim.message_id).fetch_one(&mut **tx).await?;
    let digest: [u8; 32] = serde_json::from_value(digest)?;
    let proof = Proof {
        scope,
        invitation: &state.invitation,
        object_id: claim.object_id,
        revision: state.revision,
        purpose: state.purpose,
        expires_at: state.expires_at,
        hash: &state.hash,
        purpose_binding: state.purpose_binding,
    };
    let context = producer.context(&proof, claim.message_id, digest)?;
    let (key_version, ciphertext) = outbox::admit(tx, claim, &context, selection, now).await?;
    Ok(Authorized {
        context,
        endpoint: producer.channel.endpoint,
        key_version,
        ciphertext,
        scope,
        invitation,
        object: claim.object_id,
        purpose: state.purpose,
        revision: state.revision,
        hash: state
            .hash
            .try_into()
            .map_err(|_| AuthorityError::Forbidden)?,
        recipient: state.invitation.recipient,
        issuer: producer.issuer,
        admitted_at: now,
        lease_until: claim.lease_until,
    })
}

pub(super) async fn invitation_state(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: Uuid,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<CurrentProof, RepositoryError> {
    let stored = load(tx, scope, id).await?;
    current_with_runtime(tx, scope, &stored, now, runtime).await?;
    require(stored.invitation.state == State::Pending)?;
    Ok(CurrentProof {
        hash: stored.hash.clone().unwrap_or_default(),
        revision: stored.delivery_revision,
        delivered_at: stored.delivered_at,
        purpose: cap::Purpose::Invitation,
        expires_at: stored.invitation.expires_at,
        invitation: stored,
        purpose_binding: serde_json::Value::Null,
    })
}

pub(super) async fn challenge_state(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    invitation: Uuid,
    id: Uuid,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<CurrentProof, RepositoryError> {
    let stored = load(tx, scope, invitation).await?;
    current_with_runtime(tx, scope, &stored, now, runtime).await?;
    require(stored.invitation.state == State::Pending)?;
    let row = sqlx::query("SELECT recipient_binding,invitation_delivery_revision,issued_at,expires_at,delivery_revision,delivered_at,capability_hash FROM aegaeon.organization_invitation_challenges WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3 AND id=$4 FOR UPDATE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(invitation).bind(id).fetch_one(&mut **tx).await?;
    let recipient: Recipient = serde_json::from_value(row.try_get("recipient_binding")?)?;
    recipient.check(tx, scope, now).await?;
    let expires_at = row.try_get("expires_at")?;
    let revision = row.try_get("delivery_revision")?;
    require(
        revision >= 0
            && row.try_get::<i64, _>("invitation_delivery_revision")? == stored.delivery_revision
            && cap::is_live(
                cap::Purpose::RecipientChallenge,
                row.try_get("issued_at")?,
                expires_at,
                now,
            ),
    )?;
    Ok(CurrentProof {
        invitation: stored,
        revision,
        delivered_at: row.try_get("delivered_at")?,
        purpose: cap::Purpose::RecipientChallenge,
        expires_at,
        hash: row
            .try_get::<Option<Vec<u8>>, _>("capability_hash")?
            .unwrap_or_default(),
        purpose_binding: serde_json::to_value(recipient)?,
    })
}
