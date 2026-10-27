use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Opaque identity shared by the stored descendants of one refresh grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshGrantRef {
    pub version: u32,
    pub id: String,
}

impl RefreshGrantRef {
    pub(crate) fn new() -> Self {
        Self {
            version: 1,
            id: super::generate_secure_random(32),
        }
    }

    pub(crate) fn supported(&self) -> bool {
        self.version == 1
            && self.id.len() == 43
            && self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    }
}

/// Independently retained online decision. Absence never creates authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshGrantRecord {
    pub version: u32,
    pub reference: RefreshGrantRef,
    pub client_id: String,
    pub user_id: String,
    pub revoked: bool,
    pub retain_until: SystemTime,
}

impl RefreshGrantRecord {
    pub(crate) fn matches(&self, reference: &RefreshGrantRef, client: &str, user: &str) -> bool {
        self.version == 1
            && reference.supported()
            && self.reference == *reference
            && self.client_id == client
            && self.user_id == user
    }

    pub(crate) fn active(
        &self,
        reference: &RefreshGrantRef,
        client: &str,
        user: &str,
        now: SystemTime,
    ) -> bool {
        self.matches(reference, client, user) && !self.revoked && now < self.retain_until
    }
}
