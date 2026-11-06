use super::*;

pub(in crate::web::management::organizations) async fn read_support_policy(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
) -> Response {
    execute_with_organization_management_session(
        &state,
        &headers,
        &admission,
        &context,
        Action::ReadSupportPolicy {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
        },
    )
    .await
}

pub(in crate::web::management::organizations) async fn configure_support_policy(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: http_input::support_policy::ConfigureSupportPolicyRequest =
        match http_input::decode_json(&body) {
            Ok(v) => v,
            Err(e) => return input_error(e, &context.request_id),
        };
    let expected_revision = match http_input::support_policy::required_policy_version(&headers) {
        Ok(v) => match v.require_current(domain_id, v.revision()) {
            Ok(()) => v.revision(),
            Err(e) => return input_error(e, &context.request_id),
        },
        Err(e) => return input_error(e, &context.request_id),
    };
    execute_with_organization_management_session(
        &state,
        &headers,
        &admission,
        &context,
        Action::SupportPolicy {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            change: mutations::support_policy::Change {
                expected_revision,
                policy: Some(input.policy),
            },
        },
    )
    .await
}

pub(in crate::web::management::organizations) async fn disable_support_policy(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: Reason = match http_input::decode_json(&body) {
        Ok(v) => v,
        Err(e) => return input_error(e, &context.request_id),
    };
    let expected_revision = match http_input::support_policy::required_policy_version(&headers) {
        Ok(v) => match v.require_current(domain_id, v.revision()) {
            Ok(()) => v.revision(),
            Err(e) => return input_error(e, &context.request_id),
        },
        Err(e) => return input_error(e, &context.request_id),
    };
    execute_with_organization_management_session(
        &state,
        &headers,
        &admission,
        &context,
        Action::SupportPolicy {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            change: mutations::support_policy::Change {
                expected_revision,
                policy: None,
            },
        },
    )
    .await
}

pub(super) async fn dispatch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &AuditActor,
    key: &str,
    action: Action,
) -> Result<(Vec<u8>, VersionTag), Response> {
    let result = match action {
        Action::ReadSupportPolicy { team, scope } => {
            mutations::support_policy::read(tx, scope, team, actor.id).await
        }
        Action::SupportPolicy {
            team,
            scope,
            change,
            ..
        } => mutations::support_policy::apply(tx, scope, team, actor, key, &change).await,
        _ => {
            return Err(failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                &actor.request_id,
            ))
        }
    }
    .map_err(|e| storage_error(&e, &actor.request_id))?;
    super::dispatch::encode(&result, result.id, result.revision, &actor.request_id)
}
