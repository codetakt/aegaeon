use super::PageInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AuditActor {
    pub actor_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AuditTarget {
    pub target_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AuditRequestContext {
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AuditChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_configuration_version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_configuration_version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_patch: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub team_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    pub event_type: String,
    pub category: String,
    pub outcome: String,
    pub severity: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub occurred_at: String,
    pub actor: AuditActor,
    pub target: AuditTarget,
    pub request: AuditRequestContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<AuditChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListAuditEventsResponse {
    pub audit_events: Vec<AuditEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ExportAuditEventsResponse {
    pub audit_events: Vec<AuditEvent>,
    pub total_count: u64,
    pub exported_at: String,
    pub time_range: ExportTimeRange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ExportTimeRange {
    pub from: String,
    pub to: String,
}
