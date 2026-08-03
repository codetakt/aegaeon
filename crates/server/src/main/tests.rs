use super::*;
use std::error::Error as StdError;
use std::ffi::OsString;
use std::io;
use std::sync::{Mutex, MutexGuard};

#[path = "tests/env_inventory.rs"]
mod env_inventory;
#[path = "tests/env_parsers.rs"]
mod env_parsers;
#[path = "tests/key_managers.rs"]
mod key_managers;

static ENV_LOCK: Mutex<()> = Mutex::new(());

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
    ENV_LOCK
        .lock()
        .map_err(|_| io::Error::other("environment lock poisoned"))
}

fn no_panic<T>(
    result: std::thread::Result<anyhow::Result<T>>,
    message: &'static str,
) -> std::result::Result<anyhow::Result<T>, io::Error> {
    result.map_err(|_| io::Error::other(message))
}
