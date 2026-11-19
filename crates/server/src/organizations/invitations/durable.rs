//! Initial proof issuance and encrypted mail are committed together.
//! Transport retries never call these producers or rotate the capability.
use super::*;
use crate::organizations::{
    lifecycle::Selection,
    notification_envelope::{MessageContext, PublicDeliveryKey, Revision, Scope as MailScope},
    notification_outbox::{self as outbox, Object, Prepared},
    operators::mutations::delivery as configuration,
};
use aegaeon_crypto::hash::sha256_digest;
use zeroize::Zeroizing;

mod admission;
pub(crate) use admission::{admit_current, Authorized};
mod reissue;
pub(crate) use reissue::{reissue, Reissue};

pub(super) struct Producer {
    key: PublicDeliveryKey,
    selection: Selection,
    configuration_revision: i64,
    issuer: String,
    channel: configuration::Channel,
}

impl Producer {
    pub(super) async fn current(
        tx: &mut Transaction<'_, Postgres>,
        scope: Scope,
    ) -> Result<Option<Self>, RepositoryError> {
        // Callers hold the purpose's human/domain/organization locks first.
        let config = configuration::read_locked(tx, scope).await?;
        let Some(channel) = config.channel else {
            return Ok(None);
        };
        let Some(encryption) = channel.encryption.as_ref() else {
            return Ok(None);
        };
        let selection = epoch::capture(scope)?
            .runtime_selection()
            .map_err(|_| AuthorityError::Forbidden)?;
        require(selection.deployment_id() == encryption.deployment_id)?;
        let host: String = sqlx::query_scalar(
            "SELECT issuer_host FROM aegaeon.environments WHERE id=$1 FOR SHARE",
        )
        .bind(scope.environment_id)
        .fetch_one(&mut **tx)
        .await?;
        Ok(Some(Self {
            key: encryption.public_key(scope)?,
            selection,
            configuration_revision: config.revision,
            issuer: format!("https://{host}"),
            channel,
        }))
    }

    pub(super) async fn enqueue(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        proof: Proof<'_>,
        capability: cap::Capability,
        now: i64,
    ) -> Result<Uuid, RepositoryError> {
        let message_id = Uuid::new_v4();
        let template = template(proof.purpose);
        // Borrow the secret while serializing; do not retain a Value copy.
        let capability = Zeroizing::new(capability.into_delivery());
        let payload = Payload {
            version: 2,
            message_id,
            template,
            recipient: &proof.invitation.recipient,
            issuer: &self.issuer,
            environment_id: proof.scope.environment_id,
            domain_id: proof.scope.domain_id,
            invitation_id: proof.invitation.invitation.id,
            object_id: proof.object_id,
            delivery_revision: proof.revision,
            capability: &capability,
            expires_at: proof.expires_at,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&payload)?);
        let context = self.context(&proof, message_id, sha256_digest(&plaintext))?;
        let message = Prepared::seal(
            context,
            Object {
                id: proof.object_id,
                parent: (proof.object_id != proof.invitation.invitation.id)
                    .then_some(proof.invitation.invitation.id),
            },
            &self.key,
            plaintext,
            now,
        )?;
        outbox::enqueue(tx, &message).await?;
        Ok(message_id)
    }

    fn context(
        &self,
        proof: &Proof<'_>,
        message_id: Uuid,
        payload_digest: [u8; 32],
    ) -> Result<MessageContext, RepositoryError> {
        let template = template(proof.purpose);
        Ok(MessageContext {
            message_id,
            deployment_id: self.selection.deployment_id(),
            runtime_generation: self.selection.generation(),
            scope: MailScope::Organization {
                environment_id: proof.scope.environment_id,
                domain_id: proof.scope.domain_id,
                organization_id: proof.invitation.invitation.organization_id,
            },
            organization_generation: Revision::Value(
                proof.invitation.authority.organization_generation,
            ),
            purpose: template.to_owned(),
            template: template.to_owned(),
            template_version: 2,
            expires_at: proof.expires_at,
            authority_revision: Revision::Value(proof.revision),
            contact_revision: Revision::NotApplicable,
            configuration_revision: Revision::Value(self.configuration_revision),
            authority_binding: proof.authority_digest()?,
            destination_binding: sha256_digest(proof.invitation.recipient.as_bytes()),
            payload_digest,
        })
    }
}

pub(super) struct Proof<'a> {
    pub scope: Scope,
    pub invitation: &'a Stored,
    pub object_id: Uuid,
    pub revision: i64,
    pub purpose: cap::Purpose,
    pub expires_at: i64,
    pub hash: &'a [u8],
    pub purpose_binding: serde_json::Value,
}

impl Proof<'_> {
    fn authority_digest(&self) -> Result<[u8; 32], RepositoryError> {
        require(self.hash.len() == 32 && self.revision > 0)?;
        Ok(sha256_digest(&serde_json::to_vec(&serde_json::json!({
            "profile":"aegaeon-notification-authority-v1",
            "authority":self.invitation.authority,
            "invitation":self.invitation.invitation.id,
            "invitationDeliveryRevision":self.invitation.delivery_revision,
            "object":self.object_id, "revision":self.revision,
            "purpose":template(self.purpose), "proofHash":self.hash,
            "binding":self.purpose_binding,
        }))?))
    }
}

pub(super) fn template(purpose: cap::Purpose) -> &'static str {
    match purpose {
        cap::Purpose::Invitation => "organization_invitation",
        cap::Purpose::RecipientChallenge => "organization_recipient_challenge",
        cap::Purpose::IdentityRegistration => "organization_identity_registration",
        cap::Purpose::IdentityRecovery => "organization_identity_recovery",
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Payload<'a> {
    version: u32,
    message_id: Uuid,
    template: &'a str,
    recipient: &'a str,
    issuer: &'a str,
    environment_id: Uuid,
    domain_id: Uuid,
    invitation_id: Uuid,
    object_id: Uuid,
    delivery_revision: i64,
    capability: &'a str,
    expires_at: i64,
}

pub(super) struct CurrentProof {
    pub invitation: Stored,
    pub revision: i64,
    pub delivered_at: Option<i64>,
    pub purpose: cap::Purpose,
    pub expires_at: i64,
    pub hash: Vec<u8>,
    pub purpose_binding: serde_json::Value,
}

/// Used only for a newly inserted invitation within its issuance transaction.
pub(super) async fn enqueue_invitation(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: Uuid,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<(), RepositoryError> {
    let mut stored = load(tx, scope, id).await?;
    let org = current_with_runtime(tx, scope, &stored, now, runtime).await?;
    let Some(producer) = Producer::current(tx, scope).await? else {
        return Ok(());
    };
    require(stored.delivery_revision == 0 && stored.hash.is_none())?;
    let (capability, hash) = delivery::generate(scope, id, 1, cap::Purpose::Invitation)?;
    sqlx::query("UPDATE aegaeon.organization_invitations SET delivery_revision=1,delivered_at=$2,capability_hash=$3,delivery_outcome='uncertain' WHERE id=$1")
        .bind(id).bind(now).bind(hash.as_slice()).execute(&mut **tx).await?;
    stored.delivery_revision = 1;
    let message = producer
        .enqueue(
            tx,
            Proof {
                scope,
                invitation: &stored,
                object_id: id,
                revision: 1,
                purpose: cap::Purpose::Invitation,
                expires_at: stored.invitation.expires_at,
                hash: &hash,
                purpose_binding: serde_json::Value::Null,
            },
            capability,
            now,
        )
        .await?;
    queued(tx, &org, &stored.authority.actor, id, message).await
}

pub(super) async fn enqueue_challenge(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    stored: &Stored,
    org: &Organization,
    id: Uuid,
    expires: i64,
) -> Result<bool, RepositoryError> {
    let Some(producer) = Producer::current(tx, input.scope).await? else {
        return Ok(false);
    };
    let (capability, hash) =
        delivery::generate(input.scope, id, 1, cap::Purpose::RecipientChallenge)?;
    let changed = sqlx::query("UPDATE aegaeon.organization_invitation_challenges SET delivery_revision=1,delivered_at=$2,capability_hash=$3,delivery_outcome='uncertain' WHERE id=$1 AND delivery_revision=0")
        .bind(id).bind(input.now).bind(hash.as_slice()).execute(&mut **tx).await?;
    require(changed.rows_affected() == 1)?;
    let message = producer
        .enqueue(
            tx,
            Proof {
                scope: input.scope,
                invitation: stored,
                object_id: id,
                revision: 1,
                purpose: cap::Purpose::RecipientChallenge,
                expires_at: expires,
                hash: &hash,
                purpose_binding: serde_json::to_value(input.recipient)?,
            },
            capability,
            input.now,
        )
        .await?;
    let actor = acceptance::recipient_actor(input, stored)?;
    queued(tx, org, &actor, id, message).await?;
    Ok(true)
}

pub(super) async fn queued(
    tx: &mut Transaction<'_, Postgres>,
    org: &Organization,
    actor: &AuditActor,
    object: Uuid,
    message: Uuid,
) -> Result<(), RepositoryError> {
    repo::event(
        tx,
        org,
        actor,
        "organization.notification_queued",
        serde_json::json!({"object_id":object,"message_id":message,
            "before":null,"after":{"state":"pending","attempts":0}}),
    )
    .await
}
