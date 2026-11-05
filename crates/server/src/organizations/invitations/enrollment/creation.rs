//! Authenticated current proof precedes a retained registration intent.
use super::*;
use crate::organizations::witness::creation::{Input, Kind, Receipt};
use aegaeon_crypto::hash::sha256_digest;

pub(crate) enum Preparation {
    Registration(Input),
    Recovery,
}
pub(crate) enum Creation<'a> {
    New(&'a Receipt),
    Replay(&'a Receipt),
}

pub(crate) async fn prepare_completion(
    tx: &mut Transaction<'_, Postgres>,
    input: &Completion<'_>,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Preparation, RepositoryError> {
    let current = authenticated(tx, input, runtime).await?;
    match current.purpose {
        Purpose::Registration => Ok(Preparation::Registration(binding(input, &current)?)),
        Purpose::PasswordRecovery => Ok(Preparation::Recovery),
    }
}

pub(super) async fn authenticated(
    tx: &mut Transaction<'_, Postgres>,
    input: &Completion<'_>,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Pending, RepositoryError> {
    let current = pending(
        tx,
        input.scope,
        input.invitation,
        input.request,
        input.now,
        runtime,
    )
    .await?;
    require(matches_secret(
        input.scope,
        current.id,
        current.revision,
        current.purpose.capability(),
        current.hash.as_deref(),
        input.proof,
    ))?;
    Ok(current)
}

fn text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend((value.len() as u32).to_be_bytes());
    bytes.extend(value.as_bytes());
}
fn binding(input: &Completion<'_>, current: &Pending) -> Result<Input, RepositoryError> {
    require(
        current.purpose == Purpose::Registration && current.revision > 0 && current.expires > 0,
    )?;
    let mut selector = b"aegaeon-creation-registration-selector-v1\0".to_vec();
    for id in [
        input.scope.environment_id,
        input.scope.domain_id,
        input.invitation,
        input.request,
    ] {
        selector.extend(id.as_bytes());
    }
    let mut actor = b"aegaeon-creation-registration-actor-v1\0".to_vec();
    for id in [
        input.scope.environment_id,
        input.scope.domain_id,
        current.org.id,
        input.invitation,
        input.request,
    ] {
        actor.extend(id.as_bytes());
    }
    for revision in [
        current.invitation.delivery_revision,
        current.revision,
        current.policy_revision,
    ] {
        require((1..i64::MAX).contains(&revision))?;
        actor.extend((revision as u64).to_be_bytes());
    }
    let mut payload = b"aegaeon-creation-registration-v1\0".to_vec();
    text(&mut payload, &current.invitation.recipient);
    text(
        &mut payload,
        &current.invitation.recipient.to_ascii_lowercase(),
    );
    payload.extend((current.expires as u64).to_be_bytes());
    Input::new(
        Kind::Registration,
        sha256_digest(&selector),
        sha256_digest(&actor),
        sha256_digest(&payload),
        None,
    )
    .map_err(|_| AuthorityError::Invalid.into())
}

pub(super) fn retained<'a>(
    input: &Completion<'_>,
    current: &Pending,
    creation: Option<Creation<'a>>,
) -> Result<Option<&'a Receipt>, RepositoryError> {
    if current.purpose == Purpose::PasswordRecovery {
        require(creation.is_none())?;
        return Ok(None);
    }
    let (receipt, replay) = match creation.ok_or(AuthorityError::Forbidden)? {
        Creation::New(receipt) => (receipt, false),
        Creation::Replay(receipt) => (receipt, true),
    };
    require(receipt.matches(&binding(input, current)?) && current.result.is_some() == replay)?;
    if let Some(result) = &current.result {
        require(result.user_id == receipt.owner_id() && result.subject == receipt.subject())?;
    }
    Ok(Some(receipt))
}
