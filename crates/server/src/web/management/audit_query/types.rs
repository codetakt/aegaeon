use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::web::management) struct AuditEventListQuery {
    pub(in crate::web::management) page_size: Option<u32>,
    /// Cursor-based page token: base64-encoded "`occurred_at|id`" pair
    pub(in crate::web::management) page_token: Option<String>,
    /// Filter by `event_type` (e.g. "token.issued", "client.created")
    pub(in crate::web::management) event_type: Option<String>,
    /// Filter by category (e.g. "AUTHENTICATION", "MANAGEMENT")
    pub(in crate::web::management) category: Option<String>,
    /// Filter by `target_type` (e.g. "CLIENT", "`SIGNING_KEY`")
    pub(in crate::web::management) target_type: Option<String>,
    /// Filter by action/outcome (e.g. "SUCCESS", "FAILURE")
    pub(in crate::web::management) outcome: Option<String>,
    /// Filter by severity (e.g. "INFO", "WARN", "ERROR")
    pub(in crate::web::management) severity: Option<String>,
    /// Start of time range (ISO 8601, required)
    pub(in crate::web::management) from: Option<String>,
    /// End of time range (ISO 8601, required)
    pub(in crate::web::management) to: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::web::management) struct AuditExportQuery {
    /// Filter by `event_type`
    pub(in crate::web::management) event_type: Option<String>,
    /// Filter by category
    pub(in crate::web::management) category: Option<String>,
    /// Filter by `target_type`
    pub(in crate::web::management) target_type: Option<String>,
    /// Filter by outcome
    pub(in crate::web::management) outcome: Option<String>,
    /// Filter by severity
    pub(in crate::web::management) severity: Option<String>,
    /// Start of time range (ISO 8601, required)
    pub(in crate::web::management) from: String,
    /// End of time range (ISO 8601, required)
    pub(in crate::web::management) to: String,
    /// Export format: "json" (default) or "csv"
    pub(in crate::web::management) format: Option<String>,
    /// Maximum events to export (default 1000, max 10000)
    pub(in crate::web::management) limit: Option<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::web::management) enum AuditExportFormat {
    Json,
    Csv,
}
