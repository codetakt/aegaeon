use uuid::Uuid;

use crate::management::types::ApiKeyCapability;

pub(in crate::web::management) struct ApiKeyInsertInput<'a> {
    pub(in crate::web::management) api_key_id: Uuid,
    pub(in crate::web::management) team_id: Uuid,
    pub(in crate::web::management) service_administrator_id: Uuid,
    pub(in crate::web::management) name: &'a str,
    pub(in crate::web::management) key_prefix: &'a str,
    pub(in crate::web::management) key_hash: &'a [u8],
    pub(in crate::web::management) capabilities: &'a [ApiKeyCapability],
    pub(in crate::web::management) expires_in_days: Option<i32>,
    pub(in crate::web::management) created_by_administrator_id: Uuid,
}
