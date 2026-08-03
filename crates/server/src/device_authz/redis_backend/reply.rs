use super::super::{DevicePollResult, DeviceUserCodeLookup};

pub(super) fn redis_poll_result(reply: &[String]) -> DevicePollResult {
    match reply.first().map(String::as_str) {
        Some("authorization_pending") => DevicePollResult::AuthorizationPending,
        Some("slow_down") => DevicePollResult::SlowDown,
        Some("access_denied") => DevicePollResult::AccessDenied,
        Some("invalid_target") => DevicePollResult::InvalidTarget,
        Some("approved") if reply.len() >= 7 => DevicePollResult::Approved {
            user_id: reply[1].clone(),
            scope: (reply[2] == "1").then(|| reply[3].clone()),
            resource: (reply[4] == "1").then(|| reply[5].clone()),
            client_id: reply[6].clone(),
        },
        _ => DevicePollResult::ExpiredToken,
    }
}

pub(super) fn redis_user_code_lookup_result(reply: &[String]) -> Option<DeviceUserCodeLookup> {
    (reply.len() >= 5).then(|| DeviceUserCodeLookup {
        client_id: reply[0].clone(),
        scope: (reply[1] == "1").then(|| reply[2].clone()),
        resource: (reply[3] == "1").then(|| reply[4].clone()),
    })
}
