use super::DeviceCodeStorageError;
use crate::authcode::token::AccessTokenAudiencePolicy;

#[cfg(test)]
mod tests;

/// Non-consuming snapshot. The poll script compares every field before using
/// this decision, so a concurrent change cannot authorize a different grant.
pub(super) struct DevicePollAdmission {
    pub(super) scope_present: String,
    pub(super) scope: String,
    pub(super) resource_present: String,
    pub(super) resource: String,
    pub(super) allowed: bool,
}

impl DevicePollAdmission {
    pub(super) fn read(
        conn: &mut redis::Connection,
        entry_key: &str,
        client_id: &str,
        policy: &AccessTokenAudiencePolicy,
    ) -> Result<Self, DeviceCodeStorageError> {
        let fields: [Option<String>; 4] = redis::cmd("HMGET")
            .arg(entry_key)
            .arg(&["scope_present", "scope", "resource_present", "resource"])
            .query(conn)
            .map_err(|err| DeviceCodeStorageError::BackendUnavailable(err.to_string()))?;
        let [scope_present, scope, resource_present, resource] = fields;
        // An absent record is still handled by the atomic poll's expiry path.
        if scope_present.is_none()
            && scope.is_none()
            && resource_present.is_none()
            && resource.is_none()
        {
            return Ok(Self {
                scope_present: String::new(),
                scope: String::new(),
                resource_present: String::new(),
                resource: String::new(),
                allowed: false,
            });
        }
        let invalid_record = || {
            DeviceCodeStorageError::BackendUnavailable(
                "invalid device grant resource snapshot".to_string(),
            )
        };
        let mut admission = Self {
            scope_present: scope_present.ok_or_else(invalid_record)?,
            scope: scope.ok_or_else(invalid_record)?,
            resource_present: resource_present.ok_or_else(invalid_record)?,
            resource: resource.ok_or_else(invalid_record)?,
            allowed: false,
        };
        let selected_scope = match admission.scope_present.as_str() {
            "0" => None,
            "1" => Some(admission.scope.as_str()),
            _ => return Err(invalid_record()),
        };
        let selected_resource = match admission.resource_present.as_str() {
            "0" => None,
            "1" => Some(admission.resource.as_str()),
            _ => return Err(invalid_record()),
        };
        admission.allowed = policy
            .resolve(client_id, selected_scope, selected_resource)
            .is_ok();
        Ok(admission)
    }
}
