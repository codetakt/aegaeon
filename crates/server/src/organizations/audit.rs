//! Bounded disclosure of immutable domain events; not a consistent export.
use super::{
    http_input::{self, pagination, InputError},
    operators::{lock_operator_authority, Capability},
    repository::RepositoryError,
    AuthorityError, Scope,
};
use serde::Serialize;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(crate) mod delivery;
pub(crate) mod retention;

const PAGE_BYTES: usize = 60 * 1024;
const CURSOR_KIND: &str = "audit-events.";

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", schema(as = OrganizationAuditEvent))]
pub(crate) struct Event {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    environment_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    domain_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = "uuid"))]
    organization_id: Option<Uuid>,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    actor_id: Uuid,
    actor_kind: String,
    client_id: String,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = "uuid"))]
    client_registration_id: Option<Uuid>,
    request_id: String,
    reason: String,
    event_type: String,
    created_at: String,
    data: serde_json::Value,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", schema(as = OrganizationAuditPage))]
pub(crate) struct Page {
    events: Vec<Event>,
    page_info: crate::management::types::PageInfo,
}

pub(crate) fn cursor(scope: Scope, value: Option<&str>) -> Result<Option<Uuid>, InputError> {
    let value = value
        .map(|s| s.strip_prefix(CURSOR_KIND).ok_or(InputError::Invalid))
        .transpose()?;
    pagination::decode(scope, value)
}

/// Authenticate the principal before calling. Locks prevent concurrent permission
/// changes through the final response check in the owning HTTP transaction.
pub(crate) async fn read(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    principal: Uuid,
    limit: usize,
    after: Option<Uuid>,
) -> Result<Page, RepositoryError> {
    lock_operator_authority(tx, scope, team, principal, Capability::Export).await?;
    load(tx, scope, limit, after, false, None).await
}

async fn load(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    limit: usize,
    after: Option<Uuid>,
    pending: bool,
    ids: Option<&[Uuid]>,
) -> Result<Page, RepositoryError> {
    if !(1..=http_input::MAX_PAGE_SIZE).contains(&limit) || after.is_some_and(|id| id.is_nil()) {
        return Err(AuthorityError::Invalid.into());
    }
    // Limit both row count and the bytes transferred for any persisted JSON.
    // NULL is an unsupported row, not an event silently omitted from the page.
    let rows = sqlx::query("SELECT id,organization_id,actor_id,actor_kind,client_id,client_registration_id,request_id,reason,CASE WHEN octet_length(event_type)<=255 THEN event_type ELSE NULL END AS event_type,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at,CASE WHEN octet_length(data::text)<=$4 THEN data ELSE NULL END AS data FROM aegaeon.organization_authority_events WHERE environment_id=$1 AND domain_id=$2 AND ($3::uuid IS NULL OR id>$3) AND (NOT $6 OR EXISTS (SELECT 1 FROM aegaeon.organization_authority_outbox o WHERE o.event_id=organization_authority_events.id AND o.delivered_at IS NULL)) AND ($7::uuid[] IS NULL OR id=ANY($7)) ORDER BY id LIMIT $5")
        .bind(scope.environment_id).bind(scope.domain_id).bind(after)
        .bind(PAGE_BYTES as i32).bind((limit + 1) as i64).bind(pending).bind(ids)
        .fetch_all(&mut **tx).await?;
    let mut more = rows.len() > limit;
    let mut events = Vec::with_capacity(limit);
    let mut bytes = 0usize;
    for row in rows.into_iter().take(limit) {
        let data: Option<serde_json::Value> = row.try_get("data")?;
        let event = Event {
            id: row.try_get("id")?,
            environment_id: scope.environment_id,
            domain_id: scope.domain_id,
            organization_id: row.try_get("organization_id")?,
            actor_id: row.try_get("actor_id")?,
            actor_kind: row.try_get("actor_kind")?,
            client_id: row.try_get("client_id")?,
            client_registration_id: row.try_get("client_registration_id")?,
            request_id: row.try_get("request_id")?,
            reason: row.try_get("reason")?,
            event_type: row
                .try_get::<Option<String>, _>("event_type")?
                .ok_or(RepositoryError::Unavailable)?,
            created_at: row.try_get("created_at")?,
            data: data.ok_or(RepositoryError::Unavailable)?,
        };
        let length = serde_json::to_vec(&event)?.len();
        if bytes + length > PAGE_BYTES {
            if events.is_empty() {
                return Err(RepositoryError::Unavailable);
            }
            more = true;
            break;
        }
        bytes += length;
        events.push(event);
    }
    let next = if more {
        let last = events.last().ok_or(RepositoryError::Unavailable)?;
        Some(format!(
            "{CURSOR_KIND}{}",
            pagination::encode(scope, last.id).map_err(|_| AuthorityError::Invalid)?
        ))
    } else {
        None
    };
    Ok(Page {
        events,
        page_info: crate::management::types::PageInfo {
            next_page_token: next,
        },
    })
}
