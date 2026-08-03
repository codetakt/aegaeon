use axum::response::Response;

use crate::management::types::UpdateKeyStoreRequest;

use super::audit_note::normalize_key_store_audit_note;
use super::public_config::validate_key_store_public_configuration;
use super::type_name::normalize_key_store_type;

#[derive(Clone, Debug)]
pub(in crate::web::management) struct ValidatedKeyStoreUpdate {
    pub(in crate::web::management) type_: String,
    pub(in crate::web::management) configuration: serde_json::Value,
    pub(in crate::web::management) comment: Option<String>,
    pub(in crate::web::management) allow_security_downgrade: bool,
    pub(in crate::web::management) reason: Option<String>,
}

pub(in crate::web::management) fn validate_key_store_update_request(
    req: &UpdateKeyStoreRequest,
    request_id: &str,
) -> Result<ValidatedKeyStoreUpdate, Response> {
    let type_ = normalize_key_store_type(&req.type_, request_id)?;
    let configuration =
        validate_key_store_public_configuration(&req.configuration, &type_, request_id)?;
    Ok(ValidatedKeyStoreUpdate {
        type_,
        configuration,
        comment: normalize_key_store_audit_note(req.comment.as_deref(), "comment", request_id)?,
        allow_security_downgrade: matches!(req.allow_security_downgrade, Some(true)),
        reason: normalize_key_store_audit_note(req.reason.as_deref(), "reason", request_id)?,
    })
}
