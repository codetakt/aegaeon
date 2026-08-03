use super::*;
use std::sync::{Mutex, MutexGuard};

const TEST_RSA_PRIVATE_KEY_PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/rsa2048-private.pk8.pem"
));
const TEST_RSA_PUBLIC_KEY_PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/rsa2048-public.pem"
));

type DcrTestResult = Result<(), String>;

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

fn lock_guard(mutex: &Mutex<()>) -> Result<MutexGuard<'_, ()>, String> {
    mutex
        .lock()
        .map_err(|err| format!("DCR test env guard poisoned: {err}"))
}

fn env_lock() -> Result<MutexGuard<'static, ()>, String> {
    lock_guard(&crate::util::SERVER_TEST_ENV_GUARD)
}

fn raw_json_env_lock() -> Result<MutexGuard<'static, ()>, String> {
    lock_guard(&crate::util::RAW_JSON_ENV_GUARD)
}

fn parse_client_registration(
    bytes: &[u8],
) -> Result<ClientRegistration, ClientRegistrationParseError> {
    let _guard = raw_json_env_lock().map_err(ClientRegistrationParseError::Internal)?;
    let _backend = override_raw_json_backend(
        aegaeon_jose::raw_json::RawJsonSurface::ClientRegistration,
        Some("verified-structural-v1"),
    );
    super::parse_client_registration(bytes)
}

struct EnvVarRestore {
    key: &'static str,
    previous: Option<String>,
}

impl Drop for EnvVarRestore {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn override_env_var(key: &'static str, value: Option<&str>) -> EnvVarRestore {
    let previous = std::env::var(key).ok();
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
    EnvVarRestore { key, previous }
}

fn override_raw_json_backend(
    surface: aegaeon_jose::raw_json::RawJsonSurface,
    value: Option<&str>,
) -> EnvVarRestore {
    override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(surface),
        value,
    )
}

fn override_jose_header_verified_structural_backend() -> EnvVarRestore {
    override_raw_json_backend(
        aegaeon_jose::raw_json::RawJsonSurface::JoseHeader,
        Some("verified-structural-v1"),
    )
}

fn raw_json_structural_parser_unavailable(payload: &[u8]) -> bool {
    matches!(
        ffi::raw_json_structural::parse_raw_json_structural(payload),
        Err(ffi::raw_json_structural::RawJsonStructuralParseError::ParserUnavailable)
    )
}

mod client_registration;
mod everparse;
mod redirect_uris;
mod software_statement;
mod validation;
