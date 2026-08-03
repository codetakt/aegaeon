use serde::{Deserialize, Serialize};

use super::UpstreamLogoutRelayState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RedisUpstreamLogoutRelayEntry {
    incident_id: Option<String>,
    downstream_redirect_uri: String,
    downstream_state: Option<String>,
    expires_at_epoch_secs: u64,
}

impl RedisUpstreamLogoutRelayEntry {
    pub(super) fn from_state(value: &UpstreamLogoutRelayState, expires_at_epoch_secs: u64) -> Self {
        Self {
            incident_id: value.incident_id.map(|id| id.to_string()),
            downstream_redirect_uri: value.downstream_redirect_uri.clone(),
            downstream_state: value.downstream_state.clone(),
            expires_at_epoch_secs,
        }
    }

    pub(super) fn into_state(self, now_epoch_secs: u64) -> Option<UpstreamLogoutRelayState> {
        if self.expires_at_epoch_secs <= now_epoch_secs {
            return None;
        }
        let incident_id = match self.incident_id {
            Some(id) => Some(uuid::Uuid::parse_str(&id).ok()?),
            None => None,
        };
        Some(UpstreamLogoutRelayState {
            incident_id,
            downstream_redirect_uri: self.downstream_redirect_uri,
            downstream_state: self.downstream_state,
        })
    }
}
