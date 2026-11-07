#![allow(dead_code)] // OpenAPI schema and operation markers.
use crate::openapi::types::ErrorResponse;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
#[serde(untagged)]
enum InventoryItem {
    Team(InventoryTeam),
    Tenant(InventoryTenant),
    Environment(InventoryEnvironment),
    User(InventoryUser),
    Organization(InventoryOrganization),
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InventoryTeam {
    #[schema(value_type = String, format = "uuid")]
    id: Uuid,
    name: String,
    status: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InventoryTenant {
    #[schema(value_type = String, format = "uuid")]
    id: Uuid,
    #[schema(value_type = String, format = "uuid")]
    team_id: Uuid,
    name: String,
    status: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InventoryEnvironment {
    #[schema(value_type = String, format = "uuid")]
    id: Uuid,
    #[schema(value_type = String, format = "uuid")]
    tenant_id: Uuid,
    name: String,
    issuer: Option<String>,
    status: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InventoryUser {
    #[schema(value_type = String, format = "uuid")]
    id: Uuid,
    #[schema(value_type = String, format = "uuid")]
    environment_id: Uuid,
    subject: String,
    status: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InventoryOrganization {
    #[schema(value_type = String, format = "uuid")]
    id: Uuid,
    #[schema(value_type = String, format = "uuid")]
    environment_id: Uuid,
    #[schema(value_type = String, format = "uuid")]
    domain_id: Uuid,
    external_id: String,
    state: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InventoryPageInfo {
    has_next_page: bool,
    end_cursor: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallationInventory {
    items: Vec<InventoryItem>,
    page_info: InventoryPageInfo,
}

#[utoipa::path(
    get,
    path = "/api/v1/installations/{installationId}/inventory/{resourceKind}",
    tag = "installation-inventory",
    description = "Read an explicitly selected current management grant under a consistent SQL snapshot. Team membership alone never permits installation inventory. API keys retain their Team and capability ceiling. Each page rechecks the credential and complete live grant ancestry before authorized keyset pagination; cursors expire within five minutes and are bound to principal, query and grant revisions. Items contain only the documented metadata projection; credentials, profile data and grant keys are excluded.",
    security(("managementSessionCookie"=[]), ("managementBearerApiKey"=[])),
    params(
        ("installationId" = String, Path, format = "uuid", description = "Explicit immutable installation identity"),
        ("resourceKind" = String, Path, description = "One of users, teams, tenants, environments, organizations"),
        ("grantId" = String, Query, format = "uuid", description = "One complete current grant; never a union of grants"),
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Default 100"),
        ("cursor" = Option<String>, Query, max_length = 4096, description = "Unmodified endCursor from the same principal and query")
    ),
    responses(
        (status = 200, description = "Authorized bounded metadata page; no-store", body = InstallationInventory),
        (status = 400, description = "Invalid request or stale/mismatched cursor", body = ErrorResponse),
        (status = 401, description = "Invalid or expired credential", body = ErrorResponse),
        (status = 403, description = "Installation, grant, ancestry or action refused", body = ErrorResponse),
        (status = 503, description = "Admission or database unavailable; retry only after recovery", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn list_installation_inventory() {}
