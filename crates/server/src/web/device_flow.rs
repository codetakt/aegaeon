mod authorization;
mod verification;

pub(super) use authorization::device_authorization;
pub(super) use verification::{device_approve, device_deny, device_verify_get, device_verify_post};

#[cfg(test)]
pub(super) use verification::{parse_device_user_code_query, DeviceUserCodeQueryError};
