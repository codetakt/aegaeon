mod config;
mod control_plane_policy;
mod redis_sessions;
mod runtime;
mod session_store;

pub use config::ManagementConfig;
pub use runtime::ManagementState;

#[cfg(test)]
pub(super) use config::normalize_management_allowed_origin;
#[cfg(test)]
pub(super) use control_plane_policy::MAX_MANAGEMENT_MAX_SESSIONS;
pub(in crate::web::management) use control_plane_policy::{
    load_control_plane_policy_in_transaction, ControlPlanePolicy,
};
#[cfg(test)]
pub(super) use control_plane_policy::{
    DEFAULT_MAX_SESSIONS, DEFAULT_SESSION_TTL_SECS, MAX_SESSION_TTL_SECS,
};
#[cfg(test)]
pub(super) use redis_sessions::RedisManagementSessionBackend;
#[cfg(test)]
pub(super) use redis_sessions::RedisManagementSessionKeyspace;
pub(in crate::web::management) use session_store::ManagementSession;
#[cfg(test)]
pub(super) use session_store::{ManagementSessionBackend, ManagementSessionStore};
