//! Authenticated delegated reads and updates share their primary-authority transaction.
use super::*;
use crate::organizations::{
    commands::{Command, CommandResult},
    http_input::{self, members as input, InputError, VersionTag},
    repository::{self, ActorKind, AuditActor, MembershipUpdate, RepositoryError},
    selected, AuthorityError, Binding,
};
use axum::{extract::Path, http::header};
use sqlx::Connection;
use uuid::Uuid;

mod operation;

pub(in crate::web) const LIST_PATH: &str = "/organizations/:organization/members";
pub(in crate::web) const MEMBER_PATH: &str = "/organizations/:organization/members/:user";
const READ: &str = "organization.members.read";
const MANAGE: &str = crate::organizations::delegation::MANAGE_MEMBERS;

enum Action {
    List {
        limit: usize,
        after: Option<String>,
    },
    Read {
        user: Uuid,
    },
    Update {
        command: Command,
        actor_reason: String,
        key: String,
        request_id: String,
    },
}

impl Action {
    fn privilege(&self) -> &'static str {
        if matches!(self, Self::Update { .. }) {
            MANAGE
        } else {
            READ
        }
    }
}

struct Representation {
    body: serde_json::Value,
    etag: Option<String>,
}

pub(super) fn input_error(state: &AppState, failure: InputError) -> Response {
    let status = match failure {
        InputError::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
        InputError::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
        InputError::Invalid | InputError::TooLarge => StatusCode::BAD_REQUEST,
    };
    error(state, status, "invalid_request")
}

pub(super) fn storage_error(state: &AppState, failure: &RepositoryError) -> Response {
    match failure {
        RepositoryError::Authority(
            AuthorityError::Forbidden | AuthorityError::ReauthorizationRequired,
        ) => error(state, StatusCode::FORBIDDEN, "insufficient_scope"),
        RepositoryError::Authority(AuthorityError::PreconditionFailed) => {
            error(state, StatusCode::PRECONDITION_FAILED, "invalid_request")
        }
        RepositoryError::Authority(AuthorityError::Conflict | AuthorityError::Exhausted) => {
            error(state, StatusCode::CONFLICT, "invalid_request")
        }
        RepositoryError::Authority(AuthorityError::Invalid) => {
            error(state, StatusCode::BAD_REQUEST, "invalid_request")
        }
        RepositoryError::Unavailable | RepositoryError::Storage(_) | RepositoryError::Decode(_) => {
            unavailable(state)
        }
    }
}

pub(in crate::web) async fn list(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(organization): Path<String>,
    request: Request<Body>,
) -> Response {
    handle(&state, &admission, remote, organization, None, request).await
}

pub(in crate::web) async fn member(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((organization, user)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    handle(
        &state,
        &admission,
        remote,
        organization,
        Some(user),
        request,
    )
    .await
}

async fn handle(
    state: &AppState,
    admission: &ResourceAdmission,
    remote: SocketAddr,
    organization: String,
    user: Option<String>,
    request: Request<Body>,
) -> Response {
    match execute(
        state,
        admission,
        remote,
        &organization,
        user.as_deref(),
        request,
    )
    .await
    {
        Ok(value) => {
            let mut response = super::super::token_json_response(StatusCode::OK, value.body);
            if let Some(etag) = value.etag {
                let Ok(value) = etag.parse() else {
                    return unavailable(state);
                };
                response.headers_mut().insert(header::ETAG, value);
            }
            response
        }
        Err(response) => response,
    }
}

pub(super) fn object(value: &str) -> Result<Uuid, InputError> {
    let id = Uuid::parse_str(value).map_err(|_| InputError::Invalid)?;
    if id.is_nil() || id.to_string() != value {
        return Err(InputError::Invalid);
    }
    Ok(id)
}

async fn execute(
    state: &AppState,
    admission: &ResourceAdmission,
    remote: SocketAddr,
    organization: &str,
    user: Option<&str>,
    request: Request<Body>,
) -> Result<Representation, Response> {
    state.require_subject_namespace()?;
    if state.runtime_restart.is_requested() {
        return Err(unavailable(state));
    }
    let (parts, body) = request.into_parts();
    state
        .transport
        .enforce(Some(remote), &parts.headers)
        .map_err(|kind| {
            super::super::transport_boundary::transport_rejection_for_route(
                state,
                kind,
                MEMBER_PATH,
            )
        })?;
    let organization = object(organization).map_err(|e| input_error(state, e))?;
    let user = user
        .map(object)
        .transpose()
        .map_err(|e| input_error(state, e))?;
    let method = parts.method.clone();
    let headers = parts.headers.clone();
    let query = parts.uri.query().map(str::to_owned);
    let meta = authentication::authenticate(state, admission, parts).await?;
    let action = if method == Method::PUT {
        if query.is_some()
            || http_input::one_header(&headers, "content-type")
                .map_err(|e| input_error(state, e))?
                != Some("application/json")
        {
            return Err(error(state, StatusCode::BAD_REQUEST, "invalid_request"));
        }
        let user = user.ok_or_else(|| error(state, StatusCode::BAD_REQUEST, "invalid_request"))?;
        let tag = http_input::required_version(&headers).map_err(|e| input_error(state, e))?;
        let key = http_input::idempotency_key(&headers)
            .map_err(|e| input_error(state, e))?
            .to_owned();
        let bytes = tokio::time::timeout(
            std::time::Duration::from_secs(http_input::BODY_TIMEOUT_SECONDS),
            to_bytes(body, http_input::MAX_BODY_BYTES),
        )
        .await
        .map_err(|_| error(state, StatusCode::BAD_REQUEST, "invalid_request"))?
        .map_err(|_| error(state, StatusCode::BAD_REQUEST, "invalid_request"))?;
        let value: input::UpdateMemberRequest =
            http_input::decode_json(&bytes).map_err(|e| input_error(state, e))?;
        let roles = value.validate().map_err(|e| input_error(state, e))?;
        Action::Update {
            command: Command::SetExistingMember {
                organization_id: organization,
                expected_incarnation: tag.object(),
                update: MembershipUpdate {
                    user_id: user,
                    expected_revision: tag.revision(),
                    state: value.state.into(),
                    roles,
                },
            },
            actor_reason: value.reason,
            key,
            request_id: super::super::request_id::request_id_from_headers(&headers),
        }
    } else {
        if !matches!(method, Method::GET | Method::HEAD)
            || tokio::time::timeout(
                std::time::Duration::from_secs(http_input::BODY_TIMEOUT_SECONDS),
                to_bytes(body, 0),
            )
            .await
            .map_err(|_| error(state, StatusCode::BAD_REQUEST, "invalid_request"))?
            .is_err()
        {
            return Err(error(state, StatusCode::BAD_REQUEST, "invalid_request"));
        }
        if let Some(user) = user {
            if query.is_some() {
                return Err(error(state, StatusCode::BAD_REQUEST, "invalid_request"));
            }
            Action::Read { user }
        } else {
            let (limit, after) =
                input::query(query.as_deref()).map_err(|e| input_error(state, e))?;
            Action::List { limit, after }
        }
    };
    transaction(state, admission, &meta, organization, action).await
}

async fn transaction(
    state: &AppState,
    admission: &ResourceAdmission,
    meta: &BearerTokenMeta,
    organization_id: Uuid,
    action: Action,
) -> Result<Representation, Response> {
    let authority = meta
        .selected_organization
        .as_ref()
        .ok_or_else(|| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    if !state
        .cfg
        .authorization_details_types_supported
        .iter()
        .any(|t| t == crate::organizations::ORGANIZATION_ACCESS_TYPE)
        || authority.decision.organization_id != organization_id
        || !authority.decision.privileges.contains(action.privilege())
    {
        return Err(error(state, StatusCode::FORBIDDEN, "insufficient_scope"));
    }
    let now = crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| unavailable(state))?;
    let binding = authority
        .token_binding(meta, state.environment_id, &state.issuer, now)
        .map_err(|_| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let original = meta
        .exchange_grant
        .as_ref()
        .and_then(|grant| grant.organization.as_ref())
        .ok_or_else(|| unavailable(state))?;
    let expected = super::super::organization_authority::projection(state)?;
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut connection = admission.0.connection(&state.db_pool).await.map_err(|_| unavailable(state))?;
        let mut tx = connection.as_mut().map_err(|_| unavailable(state))?.begin().await.map_err(|_| unavailable(state))?;
        if !selected::is_current(&mut tx, authority, original, &binding, now).await.map_err(|_| unavailable(state))? {
            return Err(error(state, StatusCode::UNAUTHORIZED, "invalid_token"));
        }
        let management: Option<bool> = sqlx::query_scalar("SELECT management FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 AND audience=$3 COLLATE \"C\" FOR SHARE")
            .bind(binding.scope.environment_id).bind(binding.scope.domain_id).bind(&meta.audience).fetch_optional(&mut *tx).await.map_err(|_| unavailable(state))?;
        if management != Some(true) { return Err(error(state, StatusCode::FORBIDDEN, "insufficient_scope")); }
        let value = operation::apply(&mut tx, &binding, authority, organization_id, &action, now)
            .await.map_err(|e| storage_error(state, &e))?;
        super::super::organization_authority::recheck_projection(state, &mut tx, &expected).await?;
        let commit_time = crate::util::now_unix_epoch_secs().ok().and_then(|v| i64::try_from(v).ok()).ok_or_else(|| unavailable(state))?;
        if commit_time < now || commit_time >= authority.decision.expires_at {
            return Err(error(state, StatusCode::UNAUTHORIZED, "invalid_token"));
        }
        admission.0.admit_commit().map_err(|_| unavailable(state))?;
        tx.commit().await.map_err(|_| unavailable(state))?;
        connection.release().await;
        Ok(value)
    }).await.map_err(|_| unavailable(state))?
}
