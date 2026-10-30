mod dispatch;
use super::super::http_boundary::RequestContext;
use super::{
    boundary::{failure, input_error, require_organization_management_session, storage_error},
    AppState,
};
use crate::organizations::{
    http_input::{self, VersionTag},
    operators::mutations::{self, GrantCommand},
    repository::{ActorKind, AuditActor},
    request_work::Admission,
    Scope,
};
use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use sqlx::Connection;
use uuid::Uuid;

mod clients;
mod delivery;
mod identity_policy;
mod support_policy;
pub(super) use delivery::{configure_delivery, disable_delivery, read_delivery};
pub(super) use identity_policy::{
    configure_identity_policy, disable_identity_policy, read_identity_policy,
};
pub(super) use support_policy::{
    configure_support_policy, disable_support_policy, read_support_policy,
};
mod invitations;
mod lifecycle;
mod objects;
mod recipients;
mod role_policy;
pub(super) use clients::{create_client, revoke_client, update_client};
pub(super) use invitations::{issue_invitation, read_invitation, revoke_invitation};
pub(super) use lifecycle::{disable_domain, enable_domain};
pub(super) use objects::{
    create_organization, delete_organization, prepare_administrator_recovery, read_organization,
    suspend_organization,
};
pub(super) use recipients::{replace_recipients, revoke_recipients};
pub(super) use role_policy::{read_role_policy, replace_role_policy};

use crate::organizations::http_input::{
    ConfigurationReason as Reason, CreateOperatorRequest as NewGrant,
    UpdateOperatorRequest as UpdateGrant,
};

enum Action {
    ReadSupportPolicy {
        team: Uuid,
        scope: Scope,
    },
    SupportPolicy {
        team: Uuid,
        scope: Scope,
        reason: String,
        change: mutations::support_policy::Change,
    },
    ReadIdentityPolicy {
        team: Uuid,
        scope: Scope,
    },
    IdentityPolicy {
        team: Uuid,
        scope: Scope,
        reason: String,
        change: mutations::identity_policy::Change,
    },
    ReadDelivery {
        team: Uuid,
        scope: Scope,
    },
    Delivery {
        team: Uuid,
        scope: Scope,
        reason: String,
        change: mutations::delivery::Change,
    },
    Invitation {
        team: Uuid,
        scope: Scope,
        reason: String,
        command: invitations::Command,
    },
    ReadInvitation {
        team: Uuid,
        scope: Scope,
        id: Uuid,
    },
    ReadRolePolicy {
        team: Uuid,
        scope: Scope,
    },
    ReplaceRolePolicy {
        team: Uuid,
        scope: Scope,
        reason: String,
        expected_revision: i64,
        roles: Vec<mutations::role_policy::Definition>,
    },
    Organization {
        team: Uuid,
        scope: Scope,
        reason: String,
        command: crate::organizations::commands::Command,
    },
    ReadOrganization {
        team: Uuid,
        scope: Scope,
        id: Uuid,
    },
    Recipients {
        team: Uuid,
        scope: Scope,
        reason: String,
        command: mutations::targets::recipients::ConfigureRecipients,
    },
    Domain {
        team: Uuid,
        scope: Scope,
        reason: String,
        expected_revision: i64,
        enabled: bool,
    },
    Client {
        team: Uuid,
        scope: Scope,
        reason: String,
        command: mutations::clients::ClientCommand,
    },
    ReadDomain {
        team: Uuid,
        scope: Scope,
    },
    RegisterTarget {
        team: Uuid,
        scope: Scope,
        reason: String,
        command: mutations::targets::RegisterTarget,
    },
    Bootstrap {
        team: Uuid,
        environment: Uuid,
        reason: String,
    },
    Grant {
        team: Uuid,
        scope: Scope,
        reason: String,
        command: GrantCommand,
    },
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}

pub(super) async fn configuration(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
) -> Response {
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::ReadDomain {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
        },
    )
    .await
}

pub(super) async fn register_target(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: http_input::RegisterOrganizationTargetRequest = match http_input::decode_json(&body)
    {
        Ok(value) => value,
        Err(error) => return input_error(error, &context.request_id),
    };
    let expected_revision = match version(&headers, domain_id, &context.request_id) {
        Ok(value) => value,
        Err(error) => return error,
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::RegisterTarget {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command: mutations::targets::RegisterTarget {
                expected_revision,
                target: mutations::targets::Target {
                    audience: input.audience,
                    management: input.management,
                    introspection_clients: Vec::new(),
                },
            },
        },
    )
    .await
}

pub(super) async fn bootstrap(
    State(state): State<AppState>,
    Path((team, environment)): Path<(Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: Reason = match http_input::decode_json(&body) {
        Ok(v) => v,
        Err(e) => return input_error(e, &context.request_id),
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Bootstrap {
            team,
            environment,
            reason: input.reason,
        },
    )
    .await
}

pub(super) async fn create(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: NewGrant = match http_input::decode_json(&body) {
        Ok(v) => v,
        Err(e) => return input_error(e, &context.request_id),
    };
    let command = GrantCommand::Create {
        administrator_id: input.administrator_id,
        active: input.active,
        capabilities: input.capabilities,
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Grant {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command,
        },
    )
    .await
}

pub(super) async fn update(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id, id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: UpdateGrant = match http_input::decode_json(&body) {
        Ok(v) => v,
        Err(e) => return input_error(e, &context.request_id),
    };
    let expected_revision = match version(&headers, id, &context.request_id) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let command = GrantCommand::Update {
        id,
        expected_revision,
        active: input.active,
        capabilities: input.capabilities,
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Grant {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command,
        },
    )
    .await
}

pub(super) async fn revoke(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id, id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: Reason = match http_input::decode_json(&body) {
        Ok(v) => v,
        Err(e) => return input_error(e, &context.request_id),
    };
    let expected_revision = match version(&headers, id, &context.request_id) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let command = GrantCommand::Revoke {
        id,
        expected_revision,
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Grant {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command,
        },
    )
    .await
}

fn version(headers: &HeaderMap, id: Uuid, request_id: &str) -> Result<i64, Response> {
    let version = http_input::required_version(headers).map_err(|e| input_error(e, request_id))?;
    // This compares only two client-supplied inputs. Actual representation
    // currentness is checked after authority and receipt lookup in the command.
    version
        .require_current(id, version.revision())
        .map_err(|e| input_error(e, request_id))?;
    Ok(version.revision())
}

async fn execute(
    state: &AppState,
    headers: &HeaderMap,
    admission: &Admission,
    context: &RequestContext,
    action: Action,
) -> Response {
    match transaction(state, headers, admission, context, action).await {
        Ok(response) | Err(response) => response,
    }
}

async fn transaction(
    state: &AppState,
    headers: &HeaderMap,
    admission: &Admission,
    context: &RequestContext,
    action: Action,
) -> Result<Response, Response> {
    let request_id = &context.request_id;
    let key = if matches!(
        action,
        Action::ReadDomain { .. }
            | Action::ReadDelivery { .. }
            | Action::ReadIdentityPolicy { .. }
            | Action::ReadSupportPolicy { .. }
            | Action::ReadOrganization { .. }
            | Action::ReadRolePolicy { .. }
            | Action::ReadInvitation { .. }
    ) {
        // Read-only action never enters a receipt writer.
        ""
    } else {
        http_input::idempotency_key(headers).map_err(|e| input_error(e, request_id))?
    };
    let session =
        require_organization_management_session(state, headers, admission, request_id).await?;
    let unavailable = || {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            request_id,
        )
    };
    let mut connection = admission
        .connection(&state.db_pool)
        .await
        .map_err(|_| unavailable())?;
    let mut tx = connection
        .as_mut()
        .map_err(|_| unavailable())?
        .begin()
        .await
        .map_err(|_| unavailable())?;
    let reason = action_reason(&action);
    let actor = AuditActor {
        basis: None,
        id: session.administrator_id,
        kind: ActorKind::Operator,
        client_id: "management-console".into(),
        client_registration_id: None,
        request_id: request_id.clone(),
        reason,
    };
    let support_policy = matches!(
        &action,
        Action::ReadSupportPolicy { .. } | Action::SupportPolicy { .. }
    );
    let role_policy = matches!(
        &action,
        Action::ReadRolePolicy { .. } | Action::ReplaceRolePolicy { .. }
    );
    let (value, tag) = dispatch::execute(&mut tx, &actor, key, action).await?;
    if value.len() > http_input::MAX_BODY_BYTES {
        return Err(unavailable());
    }
    let current =
        require_organization_management_session(state, headers, admission, request_id).await?;
    if current.administrator_id != session.administrator_id
        || current.created_at_epoch_secs != session.created_at_epoch_secs
    {
        return Err(failure(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            request_id,
        ));
    }
    let tag = if support_policy {
        format!(
            "\"support-policy.{}",
            tag.header_value().trim_start_matches('"')
        )
    } else if role_policy {
        format!(
            "\"role-policy.{}",
            tag.header_value().trim_start_matches('"')
        )
    } else {
        tag.header_value()
    };
    admission.admit_commit().map_err(|_| unavailable())?;
    tx.commit().await.map_err(|_| unavailable())?;
    connection.release().await;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::ETAG, tag),
        ],
        Body::from(value),
    )
        .into_response())
}

fn action_reason(action: &Action) -> String {
    match action {
        Action::ReadDomain { .. }
        | Action::ReadDelivery { .. }
        | Action::ReadIdentityPolicy { .. }
        | Action::ReadSupportPolicy { .. }
        | Action::ReadOrganization { .. }
        | Action::ReadRolePolicy { .. }
        | Action::ReadInvitation { .. } => "configuration-read".into(),
        Action::Organization { reason, .. }
        | Action::Delivery { reason, .. }
        | Action::IdentityPolicy { reason, .. }
        | Action::SupportPolicy { reason, .. }
        | Action::ReplaceRolePolicy { reason, .. }
        | Action::Invitation { reason, .. } => reason.clone(),
        Action::Bootstrap { reason, .. }
        | Action::Grant { reason, .. }
        | Action::Client { reason, .. }
        | Action::Domain { reason, .. }
        | Action::Recipients { reason, .. }
        | Action::RegisterTarget { reason, .. } => reason.clone(),
    }
}
