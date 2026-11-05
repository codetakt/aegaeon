use super::*;
use sqlx::{Postgres, Transaction};

pub(super) async fn execute(
    tx: &mut Transaction<'_, Postgres>,
    actor: &AuditActor,
    key: &str,
    action: Action,
) -> Result<(Vec<u8>, VersionTag), Response> {
    if matches!(
        &action,
        Action::ReadDelivery { .. } | Action::Delivery { .. }
    ) {
        return super::delivery::dispatch(tx, actor, key, action).await;
    }
    if matches!(
        &action,
        Action::Invitation { .. } | Action::ReadInvitation { .. }
    ) {
        return super::invitations::dispatch(tx, actor, key, action).await;
    }
    let request_id = &actor.request_id;
    match action {
        Action::Organization {
            team,
            scope,
            command,
            ..
        } => {
            let result = crate::organizations::commands::apply_operator_command(
                tx, scope, team, actor, key, &command,
            )
            .await
            .map_err(|e| storage_error(&e, request_id))?;
            let crate::organizations::commands::CommandResult::Organization(result) = result else {
                return Err(failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    request_id,
                ));
            };
            let (id, revision) = (result.id, result.revision);
            encode(
                &http_input::objects::OrganizationResponse::from(result),
                id,
                revision,
                request_id,
            )
        }
        Action::ReadOrganization { team, scope, id } => {
            crate::organizations::operators::lock_operator_authority(
                tx,
                scope,
                team,
                actor.id,
                crate::organizations::operators::Capability::Reconcile,
            )
            .await
            .map_err(|e| storage_error(&e, request_id))?;
            let result = crate::organizations::repository::lock_organization(tx, scope, id)
                .await
                .map_err(|e| storage_error(&e, request_id))?;
            let revision = result.revision;
            encode(
                &http_input::objects::OrganizationResponse::from(result),
                id,
                revision,
                request_id,
            )
        }
        Action::Bootstrap {
            team, environment, ..
        } => {
            let result = mutations::bootstrap_default(tx, team, environment, actor, key)
                .await
                .map_err(|e| storage_error(&e, request_id))?;
            let (id, revision) = (result.scope.domain_id, result.revision);
            encode(
                &http_input::DefaultDomainResponse::from(result),
                id,
                revision,
                request_id,
            )
        }
        Action::Grant {
            team,
            scope,
            command,
            ..
        } => {
            let result = mutations::apply_grant_command(tx, scope, team, actor, key, &command)
                .await
                .map_err(|e| storage_error(&e, request_id))?;
            let (id, revision) = (result.id, result.revision);
            encode(
                &http_input::OperatorGrantResponse::from(result),
                id,
                revision,
                request_id,
            )
        }
        other => configuration(tx, actor, key, other).await,
    }
}

async fn configuration(
    tx: &mut Transaction<'_, Postgres>,
    actor: &AuditActor,
    key: &str,
    action: Action,
) -> Result<(Vec<u8>, VersionTag), Response> {
    if matches!(
        &action,
        Action::ReadSupportPolicy { .. } | Action::SupportPolicy { .. }
    ) {
        return super::support_policy::dispatch(tx, actor, key, action).await;
    }
    if matches!(
        &action,
        Action::ReadIdentityPolicy { .. } | Action::IdentityPolicy { .. }
    ) {
        return super::identity_policy::dispatch(tx, actor, key, action).await;
    }
    if matches!(
        &action,
        Action::ReadRolePolicy { .. } | Action::ReplaceRolePolicy { .. }
    ) {
        return super::role_policy::dispatch(tx, actor, key, action).await;
    }
    let request_id = &actor.request_id;
    match action {
        Action::Recipients {
            team,
            scope,
            command,
            ..
        } => {
            let result =
                mutations::targets::recipients::apply(tx, scope, team, actor, key, &command)
                    .await
                    .map_err(|e| storage_error(&e, request_id))?;
            encode(&result, result.id, result.revision, request_id)
        }
        Action::Domain {
            team,
            scope,
            expected_revision,
            enabled,
            ..
        } => {
            let result = mutations::lifecycle::apply(
                tx,
                scope,
                team,
                actor,
                key,
                expected_revision,
                enabled,
            )
            .await
            .map_err(|e| storage_error(&e, request_id))?;
            encode(&result, result.id, result.revision, request_id)
        }
        Action::Client {
            team,
            scope,
            command,
            ..
        } => {
            let result = mutations::clients::apply(tx, scope, team, actor, key, &command)
                .await
                .map_err(|e| storage_error(&e, request_id))?;
            encode(&result, result.id, result.revision, request_id)
        }
        Action::ReadDomain { team, scope } => {
            let result = mutations::targets::read_configuration(tx, scope, team, actor.id)
                .await
                .map_err(|e| storage_error(&e, request_id))?;
            encode(&result, result.id, result.revision, request_id)
        }
        Action::RegisterTarget {
            team,
            scope,
            command,
            ..
        } => {
            let result = mutations::targets::register(tx, scope, team, actor, key, &command)
                .await
                .map_err(|e| storage_error(&e, request_id))?;
            encode(&result, result.id, result.revision, request_id)
        }
        _ => Err(failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            request_id,
        )),
    }
}

pub(super) fn encode(
    value: &impl serde::Serialize,
    id: Uuid,
    revision: i64,
    request_id: &str,
) -> Result<(Vec<u8>, VersionTag), Response> {
    let tag = VersionTag::new(id, revision).map_err(|e| input_error(e, request_id))?;
    let encoded = serde_json::to_vec(value).map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            request_id,
        )
    })?;
    Ok((encoded, tag))
}
