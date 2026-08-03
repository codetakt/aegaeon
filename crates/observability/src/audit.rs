use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::{error, info};

/// Audit event severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

/// Types of audit events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    // Authentication events
    AuthenticationSuccess,
    AuthenticationFailure,

    // Authorization events
    AuthorizationGranted,
    AuthorizationDenied,

    // Token events
    TokenIssued,
    TokenRevoked,
    TokenIntrospected,
    TokenRefreshed,

    // Policy events
    PolicyViolation,
    PolicyUpdated,

    // Administrative events
    AdminAction,
    ConfigurationChange,

    // Security events
    SuspiciousActivity,
    RateLimitExceeded,
    DPoPValidationFailure,
    PKCEMismatch,
}

/// Structured audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub event_id: String,

    /// Timestamp of the event
    pub timestamp: OffsetDateTime,

    /// Event type
    pub event_type: AuditEventType,

    /// Severity level
    pub severity: AuditSeverity,

    /// Actor (user/client) performing the action
    pub actor: Option<String>,

    /// Target resource
    pub resource: Option<String>,

    /// Client ID if applicable
    pub client_id: Option<String>,

    /// User ID if applicable
    pub user_id: Option<String>,

    /// IP address of the request
    pub ip_address: Option<String>,

    /// User agent string
    pub user_agent: Option<String>,

    /// Request ID for correlation
    pub request_id: Option<String>,

    /// Result of the action
    pub result: String,

    /// Additional context as JSON
    pub context: Option<serde_json::Value>,

    /// Error details if applicable
    pub error: Option<String>,
}

impl AuditEvent {
    #[must_use]
    pub fn new(event_type: AuditEventType, severity: AuditSeverity) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: OffsetDateTime::now_utc(),
            event_type,
            severity,
            actor: None,
            resource: None,
            client_id: None,
            user_id: None,
            ip_address: None,
            user_agent: None,
            request_id: None,
            result: "unknown".to_string(),
            context: None,
            error: None,
        }
    }

    #[must_use]
    pub fn with_actor(mut self, actor: String) -> Self {
        self.actor = Some(actor);
        self
    }

    #[must_use]
    pub fn with_client(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    #[must_use]
    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    #[must_use]
    pub fn with_result(mut self, result: String) -> Self {
        self.result = result;
        self
    }

    #[must_use]
    pub fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }

    #[must_use]
    pub fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = Some(context);
        self
    }
}

/// Audit logger implementation
pub struct AuditLogger {
    retention_days: u32,
    buffer: Arc<RwLock<Vec<AuditEvent>>>,
}

impl AuditLogger {
    #[must_use]
    pub fn new(retention_days: u32) -> Self {
        Self {
            retention_days,
            buffer: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Log an audit event
    pub async fn log(&self, event: AuditEvent) {
        // Log to structured logger
        match event.severity {
            AuditSeverity::Info => {
                info!(
                    event_type = ?event.event_type,
                    event_id = %event.event_id,
                    actor = ?event.actor,
                    client_id = ?event.client_id,
                    result = %event.result,
                    "Audit event"
                );
            }
            AuditSeverity::Warning => {
                info!(
                    event_type = ?event.event_type,
                    event_id = %event.event_id,
                    actor = ?event.actor,
                    client_id = ?event.client_id,
                    result = %event.result,
                    "Audit warning"
                );
            }
            AuditSeverity::Critical => {
                error!(
                    event_type = ?event.event_type,
                    event_id = %event.event_id,
                    actor = ?event.actor,
                    client_id = ?event.client_id,
                    result = %event.result,
                    error = ?event.error,
                    "Critical audit event"
                );
            }
        }

        // Also store in buffer for retrieval
        let mut buffer = self.buffer.write().await;
        buffer.push(event.clone());

        // Cleanup old events (simple implementation - in production use proper storage)
        let cutoff =
            OffsetDateTime::now_utc() - time::Duration::days(i64::from(self.retention_days));
        buffer.retain(|e| e.timestamp > cutoff);

        // In production, this would write to persistent storage (database, S3, etc.)
        // For now, we just output as JSON
        if let Ok(json) = serde_json::to_string(&event) {
            println!("AUDIT: {json}");
        }
    }

    /// Query audit logs
    pub async fn query(
        &self,
        start: OffsetDateTime,
        end: OffsetDateTime,
        event_type: Option<AuditEventType>,
        client_id: Option<String>,
    ) -> Vec<AuditEvent> {
        let buffer = self.buffer.read().await;

        buffer
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .filter(|e| {
                #[allow(clippy::unnecessary_map_or)]
                event_type.as_ref().map_or(true, |et| {
                    std::mem::discriminant(&e.event_type) == std::mem::discriminant(et)
                })
            })
            .filter(|e| {
                #[allow(clippy::unnecessary_map_or)]
                client_id
                    .as_ref()
                    .map_or(true, |cid| e.client_id.as_ref() == Some(cid))
            })
            .cloned()
            .collect()
    }
}
