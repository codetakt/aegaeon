use uuid::Uuid;

use crate::management::types::ApiKeyCapability;

pub(in crate::web::management::api_keys) struct ApiKeyInsertInput<'a> {
    pub(in crate::web::management::api_keys) api_key_id: Uuid,
    pub(in crate::web::management::api_keys) team_id: Uuid,
    pub(in crate::web::management::api_keys) service_administrator_id: Uuid,
    pub(in crate::web::management::api_keys) name: &'a str,
    pub(in crate::web::management::api_keys) key_prefix: &'a str,
    pub(in crate::web::management::api_keys) key_hash: &'a [u8],
    pub(in crate::web::management::api_keys) capabilities: &'a [ApiKeyCapability],
    pub(in crate::web::management::api_keys) expires_in_days: Option<i32>,
    pub(in crate::web::management::api_keys) created_by_administrator_id: Uuid,
}
