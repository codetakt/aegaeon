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

fn env_lock() -> std::result::Result<MutexGuard<'static, ()>, io::Error> {
    // Startup fixtures also replace the key-encryption environment. Use the
    // same lock as KMS/key-encryption fixtures for their complete lifetime,
    // including restoration by EnvVarGuard, instead of a module-local lock.
    crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| io::Error::other("environment lock poisoned"))
}

#[test]
fn startup_environment_lock_excludes_key_encryption_writers() -> TestResult {
    let _guard = env_lock()?;
    let excluded = std::thread::spawn(|| {
        matches!(
            crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        )
    })
    .join()
    .map_err(|_| io::Error::other("key-encryption contender panicked"))?;
    assert!(excluded, "startup and KMS fixtures must share exclusion");
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
