use super::*;
use std::error::Error as StdError;
use std::ffi::OsString;
use std::io;
use std::sync::MutexGuard;

#[path = "tests/env_inventory.rs"]
mod env_inventory;
#[path = "tests/env_parsers.rs"]
mod env_parsers;
#[path = "tests/key_managers.rs"]
mod key_managers;

type TestResult = std::result::Result<(), Box<dyn StdError>>;

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    fn new(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var_os(key);
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

struct MainEnvLock {
    _server: MutexGuard<'static, ()>,
    _raw_json: MutexGuard<'static, ()>,
    _key_encryption: MutexGuard<'static, ()>,
}

fn env_lock() -> std::result::Result<MainEnvLock, io::Error> {
    // Startup reads the same configuration as the config fixtures and also
    // replaces key-encryption inputs. Keep both existing lock orders: server
    // before raw JSON, and server before key encryption, through restoration.
    let server = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|_| io::Error::other("server environment lock poisoned"))?;
    let raw_json = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| io::Error::other("raw JSON environment lock poisoned"))?;
    let key_encryption = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| io::Error::other("key-encryption environment lock poisoned"))?;
    Ok(MainEnvLock {
        _server: server,
        _raw_json: raw_json,
        _key_encryption: key_encryption,
    })
}

#[test]
fn startup_environment_lock_excludes_configuration_and_key_writers() -> TestResult {
    let _guard = env_lock()?;
    let excluded = std::thread::spawn(|| {
        [
            &crate::util::SERVER_TEST_ENV_GUARD,
            &crate::util::RAW_JSON_ENV_GUARD,
            &crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD,
        ]
        .map(|guard| matches!(guard.try_lock(), Err(std::sync::TryLockError::WouldBlock)))
    })
    .join()
    .map_err(|_| io::Error::other("environment contender panicked"))?;
    assert_eq!(
        excluded, [true; 3],
        "startup, config, raw JSON and KMS fixtures must share exclusion"
    );
    Ok(())
}

fn no_panic<T>(
    result: std::thread::Result<anyhow::Result<T>>,
    message: &'static str,
) -> std::result::Result<anyhow::Result<T>, io::Error> {
    result.map_err(|_| io::Error::other(message))
}

#[path = "tests/access_verifier.rs"]
mod access_verifier;
