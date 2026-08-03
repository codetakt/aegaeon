mod create;
mod update;

use super::super::connections_support::{ConnectionClientSecretAction, ConnectionInput};
use crate::management::types::Connection;
use uuid::Uuid;

pub(super) use create::prepare_connection_create;
pub(super) use update::prepare_connection_update;

#[derive(Clone, Debug)]
pub(super) struct PreparedConnectionCreate {
    pub(super) input: ConnectionInput,
    pub(super) configuration_version_id: Uuid,
    pub(super) oauth_profile_id: Option<Uuid>,
    pub(super) client_secret_action: ConnectionClientSecretAction,
}

#[derive(Clone, Debug)]
pub(super) struct PreparedConnectionUpdate {
    pub(super) existing_connection: Connection,
    pub(super) input: ConnectionInput,
    pub(super) configuration_version_id: Uuid,
    pub(super) oauth_profile_id: Option<Uuid>,
    pub(super) client_secret_action: ConnectionClientSecretAction,
}
