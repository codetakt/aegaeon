mod creation;
mod lifecycle;
mod load;

pub(in crate::web) use creation::create_upstream_logout_incident;
pub(in crate::web) use lifecycle::load_active_logout_recovery_policy_for_connection;
pub(super) use lifecycle::{
    update_upstream_logout_incident_status, UpstreamLogoutIncidentTransition,
};
pub(super) use load::load_upstream_logout_incident_by_hash;

pub(super) fn scoped_environment() -> Result<Option<uuid::Uuid>, sqlx::Error> {
    crate::organizations::request_work::async_store::task_owner()?
        .map(|owner| {
            owner.require_store_scope()?;
            Ok(owner.epoch_binding()?.environment_id())
        })
        .transpose()
}
