use super::*;

type DeviceTestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_ok {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(value) => value,
            Err(err) => fail_test!("{}: {:?}", $context, err),
        }
    };
}

macro_rules! must_err {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(_) => fail_test!("{}", $context),
            Err(err) => err,
        }
    };
}

#[track_caller]
fn fail_assertion(message: String) -> ! {
    std::panic::panic_any(message)
}

fn approve(store: &DeviceCodeStore, user_code: &str, user_id: &str) -> bool {
    match store.try_approve(user_code, user_id) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!(
            "in-memory device approval should not fail: {err:?}"
        )),
    }
}

fn deny(store: &DeviceCodeStore, user_code: &str) -> bool {
    match store.try_deny(user_code) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!("in-memory device denial should not fail: {err:?}")),
    }
}

fn lookup_by_user_code(store: &DeviceCodeStore, user_code: &str) -> Option<DeviceUserCodeLookup> {
    match store.try_lookup_by_user_code(user_code) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!(
            "in-memory user-code lookup should not fail: {err:?}"
        )),
    }
}

fn poll_device_code(
    store: &DeviceCodeStore,
    device_code: &str,
    client_id: &str,
    environment_id: Option<&str>,
    requested_resource: Option<&str>,
) -> DevicePollResult {
    match store.try_poll(device_code, client_id, environment_id, requested_resource) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!("device poll should not fail: {err:?}")),
    }
}

fn validate_csrf(store: &CsrfTokenStore, token: &str) -> bool {
    match store.try_validate(token) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!(
            "in-memory CSRF validation should not fail: {err:?}"
        )),
    }
}

mod code_generation;
mod csrf;
mod redis_device_code;
mod rendering;
mod store_flow;
