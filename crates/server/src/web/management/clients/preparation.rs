mod create;
mod merge;
mod oauth_profile;
mod update;

use super::super::client_input::ClientInput;
use uuid::Uuid;

pub(super) use create::prepare_client_create;
pub(super) use merge::merge_client_update;
pub(super) use update::prepare_client_update;

#[derive(Clone, Debug)]
pub(in crate::web::management::clients) struct PreparedClientCreate {
    pub(in crate::web::management::clients) input: ClientInput,
    pub(in crate::web::management::clients) configuration_version_id: Uuid,
}

#[derive(Clone, Debug)]
pub(in crate::web::management::clients) struct ClientUpdateInput {
    name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    allowed_grant_types: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    token_endpoint_authentication_method: Option<String>,
    oauth_profile_change: Option<ClientOAuthProfileChange>,
}

#[derive(Clone, Debug)]
pub(in crate::web::management::clients) struct PreparedClientUpdate {
    pub(in crate::web::management::clients) input: ClientUpdateInput,
    pub(in crate::web::management::clients) configuration_version_id: Uuid,
}

#[derive(Clone, Copy, Debug)]
enum ClientOAuthProfileChange {
    Assign(Uuid),
    Clear,
}
