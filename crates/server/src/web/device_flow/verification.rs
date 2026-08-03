mod action_admission;
mod actions;
mod response;
mod user_code;

pub(in crate::web) use actions::{device_approve, device_deny};
pub(in crate::web) use user_code::{device_verify_get, device_verify_post};

#[cfg(test)]
pub(in crate::web) use user_code::{parse_device_user_code_query, DeviceUserCodeQueryError};
