use super::super::auth_session::UpstreamLogoutSession;
use crate::upstream::UpstreamLogoutRecoveryPolicy;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::web::upstream_logout_incidents) enum UpstreamLogoutIncidentStatus {
    Pending,
    Completed,
    Expired,
    CallbackRejected,
    OperatorCleared,
}

impl UpstreamLogoutIncidentStatus {
    pub(in crate::web::upstream_logout_incidents) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Expired => "expired",
            Self::CallbackRejected => "callback_rejected",
            Self::OperatorCleared => "operator_cleared",
        }
    }

    pub(in crate::web::upstream_logout_incidents) fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "completed" => Some(Self::Completed),
            "expired" => Some(Self::Expired),
            "callback_rejected" => Some(Self::CallbackRejected),
            "operator_cleared" => Some(Self::OperatorCleared),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::web::upstream_logout_incidents) struct UpstreamLogoutIncidentRecord {
    pub(in crate::web::upstream_logout_incidents) id: uuid::Uuid,
    pub(in crate::web::upstream_logout_incidents) team_id: uuid::Uuid,
    pub(in crate::web::upstream_logout_incidents) tenant_id: uuid::Uuid,
    pub(in crate::web::upstream_logout_incidents) environment_id: uuid::Uuid,
    pub(in crate::web::upstream_logout_incidents) connection_id: Option<uuid::Uuid>,
    pub(in crate::web::upstream_logout_incidents) upstream_issuer: String,
    pub(in crate::web::upstream_logout_incidents) recovery_policy: UpstreamLogoutRecoveryPolicy,
    pub(in crate::web::upstream_logout_incidents) status: UpstreamLogoutIncidentStatus,
    pub(in crate::web::upstream_logout_incidents) downstream_redirect_uri: String,
    pub(in crate::web::upstream_logout_incidents) downstream_state: Option<String>,
    pub(in crate::web::upstream_logout_incidents) is_expired: bool,
}

pub(in crate::web) struct UpstreamLogoutIncidentRequest<'a> {
    pub(in crate::web) session: &'a UpstreamLogoutSession,
    pub(in crate::web) downstream_client_id: Option<&'a str>,
    pub(in crate::web) downstream_redirect_uri: &'a str,
    pub(in crate::web) downstream_state: Option<&'a str>,
    pub(in crate::web) relay_token: &'a str,
    pub(in crate::web) relay_ttl_secs: u64,
    pub(in crate::web) actor_id: Option<&'a str>,
    pub(in crate::web) request_id: &'a str,
}

pub(in crate::web) fn hash_upstream_logout_secret(value: &str) -> String {
    let digest = aegaeon_crypto::hash::sha256_digest(value.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}
