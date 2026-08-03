use super::super::DeviceAuthzStatus;
use super::model::DeviceCodeStorageError;

pub(super) fn retention_millis(
    expires_at_ms: u64,
    now_ms: u64,
) -> Result<i64, DeviceCodeStorageError> {
    expires_at_ms
        .saturating_sub(now_ms)
        .max(1)
        .try_into()
        .map_err(|_| DeviceCodeStorageError::RetentionOverflow)
}

pub(super) fn option_present(value: Option<&str>) -> &'static str {
    if value.is_some() {
        "1"
    } else {
        "0"
    }
}

pub(super) fn option_value(value: Option<&str>) -> &str {
    value.unwrap_or("")
}

pub(super) fn status_fields(status: &DeviceAuthzStatus) -> (&'static str, &str) {
    match status {
        DeviceAuthzStatus::Pending => ("pending", ""),
        DeviceAuthzStatus::Approved { user_id, .. } => ("approved", user_id.as_str()),
        DeviceAuthzStatus::Denied => ("denied", ""),
        DeviceAuthzStatus::Expired => ("expired", ""),
    }
}
