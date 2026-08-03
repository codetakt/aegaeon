use crate::upstream::{UpstreamClaimReleasePolicy, UpstreamLogoutRecoveryPolicy};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::web) struct UpstreamLogoutSession {
    pub(in crate::web) issuer: String,
    pub(in crate::web) end_session_endpoint: Option<String>,
    pub(in crate::web) back_channel: bool,
    pub(in crate::web) session_hint_claim: Option<String>,
    pub(in crate::web) session_hint_value: Option<String>,
    pub(in crate::web) recovery_policy: UpstreamLogoutRecoveryPolicy,
    pub(in crate::web) team_id: Option<uuid::Uuid>,
    pub(in crate::web) tenant_id: Option<uuid::Uuid>,
    pub(in crate::web) environment_id: Option<uuid::Uuid>,
    pub(in crate::web) connection_id: Option<uuid::Uuid>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::web) struct AuthSession {
    pub(in crate::web) user_id: String,
    pub(in crate::web) created_at_epoch_secs: u64,
    pub(in crate::web) auth_time_epoch_secs: u64,
    pub(in crate::web) expires_at_epoch_secs: u64,
    pub(in crate::web) acr: Option<String>,
    pub(in crate::web) claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    pub(in crate::web) upstream_logout: Option<UpstreamLogoutSession>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::web) struct AuthSessionTimes {
    pub(in crate::web) created_at_epoch_secs: u64,
    pub(in crate::web) auth_time_epoch_secs: u64,
}

impl AuthSessionTimes {
    pub(in crate::web) fn local(now_epoch_secs: u64) -> Self {
        Self {
            created_at_epoch_secs: now_epoch_secs,
            auth_time_epoch_secs: now_epoch_secs,
        }
    }

    pub(in crate::web) fn from_upstream(
        created_at_epoch_secs: u64,
        upstream_auth_time_epoch_secs: i64,
    ) -> Option<Self> {
        let auth_time_epoch_secs = u64::try_from(upstream_auth_time_epoch_secs).ok()?;
        if auth_time_epoch_secs > created_at_epoch_secs {
            return None;
        }
        Some(Self {
            created_at_epoch_secs,
            auth_time_epoch_secs,
        })
    }
}
