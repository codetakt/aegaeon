#[path = "support/server_process_env.rs"]
mod server_process_env;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::sync::{LazyLock, Mutex, MutexGuard};

const REMOTE_DATABASE_URL: &str = "postgres://db.example/aegaeon?sslmode=verify-full";

static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner())
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    fn remove(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, previous }
    }

    fn set(key: &'static str, value: &'static str) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[test]
fn database_url_gate_accepts_only_postgresql_urls() {
    let _env_lock = env_lock();
    let _primary = EnvVarGuard::remove("AEGAEON_DATABASE_URL");

    assert!(server_process_env::database_url_configured_with(&[(
        "AEGAEON_DATABASE_URL",
        " postgres://db.example/aegaeon?sslmode=verify-full ",
    )]));
    assert!(!server_process_env::database_url_configured_with(&[(
        "AEGAEON_DATABASE_URL",
        "postgres://db.example/aegaeon",
    )]));
    assert!(!server_process_env::database_url_configured_with(&[(
        "AEGAEON_DATABASE_URL",
        "mysql://db.example/aegaeon",
    )]));
    assert!(!server_process_env::database_url_configured_with(&[(
        "DATABASE_URL",
        "postgresql://db.example/aegaeon",
    )]));
    assert!(!server_process_env::database_url_configured_with(&[(
        "AEGAEON_DATABASE_URL",
        "   ",
    )]));
}

#[test]
fn server_process_runtime_gate_requires_postgres_and_redis() {
    let _env_lock = env_lock();
    let _primary = EnvVarGuard::remove("AEGAEON_DATABASE_URL");
    let _test_redis = EnvVarGuard::remove("AEGAEON_TEST_REDIS_URL");
    let _legacy_redis = EnvVarGuard::remove("REDIS_URL");

    assert!(
        server_process_env::skip_without_server_process_runtime_with_env(
            "runtime gate",
            &[("AEGAEON_DATABASE_URL", REMOTE_DATABASE_URL)],
        )
    );
    assert!(
        !server_process_env::skip_without_server_process_runtime_with_env(
            "runtime gate",
            &[
                ("AEGAEON_DATABASE_URL", REMOTE_DATABASE_URL),
                ("AEGAEON_TEST_REDIS_URL", "rediss://redis.example/0"),
            ],
        )
    );
    assert!(
        !server_process_env::skip_without_server_process_runtime_with_env(
            "runtime gate",
            &[
                ("AEGAEON_DATABASE_URL", REMOTE_DATABASE_URL),
                ("AEGAEON_TEST_REDIS_URL", "redis://127.0.0.1:6379/0"),
            ],
        )
    );
    assert!(
        server_process_env::skip_without_server_process_runtime_with_env(
            "runtime gate",
            &[
                ("AEGAEON_DATABASE_URL", REMOTE_DATABASE_URL),
                ("AEGAEON_TEST_REDIS_URL", "redis://redis.example/0"),
            ],
        ),
        "non-loopback redis:// must not satisfy server-process runtime prerequisites"
    );
    assert!(
        server_process_env::skip_without_server_process_runtime_with_env(
            "runtime gate",
            &[
                ("AEGAEON_DATABASE_URL", REMOTE_DATABASE_URL),
                ("AEGAEON_TEST_REDIS_URL", "rediss:0"),
            ],
        ),
        "hostless rediss:// must not satisfy server-process runtime prerequisites"
    );
}

#[test]
fn server_process_runtime_gate_ignores_legacy_redis_url() {
    let _env_lock = env_lock();
    let _primary = EnvVarGuard::remove("AEGAEON_DATABASE_URL");
    let _test_redis = EnvVarGuard::remove("AEGAEON_TEST_REDIS_URL");
    let _legacy_redis = EnvVarGuard::set("REDIS_URL", "redis://redis.example/0");

    assert!(
        server_process_env::skip_without_server_process_runtime_with_env(
            "runtime gate",
            &[("AEGAEON_DATABASE_URL", REMOTE_DATABASE_URL)],
        ),
        "legacy REDIS_URL must not satisfy server-process runtime prerequisites"
    );
}

#[test]
fn shared_runtime_store_env_expands_test_redis_url() {
    let _env_lock = env_lock();
    let _test_redis = EnvVarGuard::set("AEGAEON_TEST_REDIS_URL", "rediss://redis.example/0");

    let expanded = server_process_env::shared_runtime_store_env(&[]);

    assert!(
        expanded
            .iter()
            .any(|(key, value)| *key == "AEGAEON_PAR_REDIS_URL"
                && value == "rediss://redis.example/0")
    );
    assert!(expanded.iter().any(|(key, value)| {
        *key == "AEGAEON_TOKEN_STORE_REDIS_URL" && value == "rediss://redis.example/0"
    }));
    assert!(expanded.iter().any(
        |(key, value)| *key == "AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL"
            && value == "rediss://redis.example/0"
    ));
    assert!(
        expanded
            .iter()
            .all(|(key, _)| *key != "AEGAEON_FEDERATION_LIST_RATE_LIMIT_REDIS_URL"),
        "server process tests must not reintroduce removed Federation OP list Redis env"
    );
    assert_eq!(
        expanded.len(),
        expanded
            .iter()
            .map(|(key, _)| *key)
            .collect::<BTreeSet<_>>()
            .len(),
        "server process runtime-store Redis env keys should be unique"
    );
}
