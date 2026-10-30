//! One explicit, bounded runtime delivery invocation; no background retry.
use super::{organization_authority, AppState};
use crate::organizations::{
    invitations::{enrollment::delivery as identity, transport, worker},
    request_work::Admission,
    Scope,
};
use sqlx::Connection;
use uuid::Uuid;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OrganizationDeliveryRequest {
    pub domain_id: Uuid,
    pub invitation_id: Uuid,
    pub challenge_id: Option<Uuid>,
    pub identity_request_id: Option<Uuid>,
    pub credential: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationDeliveryResult {
    pub invitation_id: Uuid,
    pub challenge_id: Option<Uuid>,
    pub identity_request_id: Option<Uuid>,
    pub outcome: &'static str,
}

impl AppState {
    /// Send one pending, currently authorized invitation envelope.
    /// The caller supplies the independently provisioned private transport credential.
    ///
    /// # Errors
    /// Refuses missing/currentness authority, invalid configuration and supplier failures.
    pub async fn deliver_organization_invitation(
        &self,
        input: OrganizationDeliveryRequest,
    ) -> anyhow::Result<OrganizationDeliveryResult> {
        tokio::time::timeout(std::time::Duration::from_secs(45), execute(self, input))
            .await
            .map_err(|_| anyhow::anyhow!("organization delivery deadline exceeded"))?
            .map_err(|()| anyhow::anyhow!("organization delivery unavailable"))
    }
}

fn now() -> Result<i64, ()> {
    crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or(())
}

async fn execute(
    state: &AppState,
    mut input: OrganizationDeliveryRequest,
) -> Result<OrganizationDeliveryResult, ()> {
    prerequisites(state, &input)?;
    let credential = transport::Credential::parse(std::mem::take(&mut input.credential))?;
    let client = transport::client()?;
    let scope = Scope {
        environment_id: state.environment_id,
        domain_id: input.domain_id,
    };
    let admission = Admission::try_acquire().map_err(|_| ())?;
    let expected = organization_authority::projection(state).map_err(|_| ())?;
    let mut connection = admission.connection(&state.db_pool).await.map_err(|_| ())?;
    let mut tx = connection
        .as_mut()
        .map_err(|_| ())?
        .begin()
        .await
        .map_err(|_| ())?;
    let runtime = crate::organizations::invitations::delegated::Runtime {
        store: &state.tokens.store,
        admission: &admission,
        issuer: &state.issuer,
    };
    let claimed = claim(&mut tx, scope, &input, &credential.digest(), &runtime).await?;
    organization_authority::recheck_projection(state, &mut tx, &expected)
        .await
        .map_err(|_| ())?;
    crate::organizations::invitations::recheck(
        &mut tx,
        scope,
        input.invitation_id,
        now()?,
        &runtime,
    )
    .await
    .map_err(|_| ())?;
    admission.admit_commit().map_err(|_| ())?;
    tx.commit().await.map_err(|_| ())?;
    let Some((claim, delivery)) = claimed else {
        connection.release().await;
        return Ok(OrganizationDeliveryResult {
            invitation_id: input.invitation_id,
            challenge_id: input.challenge_id,
            identity_request_id: input.identity_request_id,
            outcome: "idle",
        });
    };
    // Only the known successful commit above releases a secret for a send.
    state.require_subject_namespace().map_err(|_| ())?;
    let mut tx = connection
        .as_mut()
        .map_err(|_| ())?
        .begin()
        .await
        .map_err(|_| ())?;
    match &claim {
        Claim::Invitation(c) => {
            worker::admit_send_current(&mut tx, c, now()?, Some(&runtime)).await
        }
        Claim::Identity(c) => identity::admit_send(&mut tx, c, now()?, Some(&runtime)).await,
    }
    .map_err(|_| ())?;
    organization_authority::recheck_projection(state, &mut tx, &expected)
        .await
        .map_err(|_| ())?;
    admission.admit_commit().map_err(|_| ())?;
    tx.commit().await.map_err(|_| ())?;
    let outcome = match &claim {
        Claim::Invitation(c) => {
            transport::send(&client, c, delivery, &credential, &state.issuer).await
        }
        Claim::Identity(c) => {
            transport::send_identity(&client, c, delivery, &credential, &state.issuer).await
        }
    };
    let mut tx = connection
        .as_mut()
        .map_err(|_| ())?
        .begin()
        .await
        .map_err(|_| ())?;
    let recorded = match &claim {
        Claim::Invitation(c) => worker::complete(&mut tx, c, outcome).await,
        Claim::Identity(c) => identity::complete(&mut tx, c, outcome).await,
    }
    .map_err(|_| ())?;
    admission.admit_commit().map_err(|_| ())?;
    tx.commit().await.map_err(|_| ())?;
    connection.release().await;
    Ok(result(&input, recorded, outcome))
}

fn prerequisites(state: &AppState, input: &OrganizationDeliveryRequest) -> Result<(), ()> {
    state.require_subject_namespace().map_err(|_| ())?;
    if !state
        .cfg
        .authorization_details_types_supported
        .iter()
        .any(|t| t == crate::organizations::ORGANIZATION_ACCESS_TYPE)
        || input.domain_id.is_nil()
        || input.invitation_id.is_nil()
        || input.challenge_id.is_some_and(|id| id.is_nil())
        || input.identity_request_id.is_some_and(|id| id.is_nil())
        || (input.challenge_id.is_some() && input.identity_request_id.is_some())
    {
        return Err(());
    }
    Ok(())
}

enum Claim {
    Invitation(worker::Claim),
    Identity(identity::Claim),
}

async fn claim(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: Scope,
    input: &OrganizationDeliveryRequest,
    digest: &str,
    runtime: &crate::organizations::invitations::delegated::Runtime<'_>,
) -> Result<Option<(Claim, crate::organizations::invitations::Delivery)>, ()> {
    Ok(if let Some(id) = input.identity_request_id {
        identity::claim(
            tx,
            scope,
            input.invitation_id,
            id,
            digest,
            now()?,
            Some(runtime),
        )
        .await
        .map_err(|_| ())?
        .map(|(c, d)| (Claim::Identity(c), d))
    } else {
        worker::claim_current(
            tx,
            scope,
            input.invitation_id,
            input.challenge_id,
            digest,
            now()?,
            Some(runtime),
        )
        .await
        .map_err(|_| ())?
        .map(|(c, d)| (Claim::Invitation(c), d))
    })
}

fn result(
    input: &OrganizationDeliveryRequest,
    recorded: bool,
    outcome: worker::Outcome,
) -> OrganizationDeliveryResult {
    OrganizationDeliveryResult {
        invitation_id: input.invitation_id,
        challenge_id: input.challenge_id,
        identity_request_id: input.identity_request_id,
        outcome: if !recorded {
            "superseded"
        } else {
            match outcome {
                worker::Outcome::Acknowledged => "acknowledged",
                worker::Outcome::Rejected => "rejected",
                worker::Outcome::Uncertain => "uncertain",
            }
        },
    }
}
