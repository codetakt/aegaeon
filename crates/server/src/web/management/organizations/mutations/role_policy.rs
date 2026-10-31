use super::*;

pub(in crate::web::management::organizations) async fn read_role_policy(
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
        Action::ReadRolePolicy {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
        },
    )
    .await
}

pub(in crate::web::management::organizations) async fn replace_role_policy(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: http_input::role_policy::ReplaceRolePolicyRequest =
        match http_input::decode_json(&body) {
            Ok(value) => value,
            Err(error) => return input_error(error, &context.request_id),
        };
    let expected = match http_input::role_policy::required_policy_version(&headers) {
        Ok(value) => value,
        Err(error) => return input_error(error, &context.request_id),
    };
    if let Err(error) = expected.require_current(domain_id, expected.revision()) {
        return input_error(error, &context.request_id);
    }
    execute_with_organization_management_session(
        &state,
        &headers,
        &admission,
        &context,
        Action::ReplaceRolePolicy {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            expected_revision: expected.revision(),
            roles: input.roles,
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
        Action::ReadRolePolicy { team, scope } => {
            mutations::role_policy::read(tx, scope, team, actor.id).await
        }
        Action::ReplaceRolePolicy {
            team,
            scope,
            expected_revision,
            roles,
            ..
        } => {
            mutations::role_policy::apply(tx, scope, team, actor, key, expected_revision, &roles)
                .await
        }
        _ => {
            return Err(failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                &actor.request_id,
            ))
        }
    }
    .map_err(|error| storage_error(&error, &actor.request_id))?;
    super::dispatch::encode(&result, result.id, result.revision, &actor.request_id)
}
