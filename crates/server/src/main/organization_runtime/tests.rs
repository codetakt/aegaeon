use super::*;

#[path = "tests/background.rs"]
mod background;
#[path = "tests/http.rs"]
mod http;
#[path = "tests/packaged.rs"]
mod packaged;

#[path = "tests/delivery.rs"]
mod delivery;
#[path = "tests/delivery_packaged.rs"]
mod delivery_packaged;
#[path = "tests/delivery_setup.rs"]
mod delivery_setup;
#[path = "tests/fixture.rs"]
mod fixture;
#[path = "tests/startup.rs"]
mod startup;
#[path = "tests/store_restart.rs"]
mod store_restart;

struct EnvVarGuard(&'static str, Option<std::ffi::OsString>);
impl EnvVarGuard {
    fn new(key: &'static str, value: Option<&str>) -> Self {
        let old = std::env::var_os(key);
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        Self(key, old)
    }
}
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.1 {
            Some(value) => std::env::set_var(self.0, value),
            None => std::env::remove_var(self.0),
        }
    }
}

// The process environment is shared with other test modules. Serialize before
// starting the runtime, so no executor thread blocks on this synchronous lock.
fn with_environment<T, F>(mut runtime: tokio::runtime::Builder, operation: impl FnOnce() -> F) -> T
where
    F: std::future::Future<Output = T>,
{
    let _guard = crate::util::SERVER_TEST_ENV_GUARD.lock().unwrap();
    runtime.enable_all().build().unwrap().block_on(operation())
}

#[test]
fn organization_delivery_requires_independent_configuration_before_bootstrap() {
    with_environment(tokio::runtime::Builder::new_current_thread(), || async {
        let _guard = EnvVarGuard::new("AEGAEON_ORGANIZATION_RUNTIME_CONFIG", None);
        let request = || OrganizationDeliveryRequest {
            domain_id: Uuid::new_v4(),
            invitation_id: Uuid::new_v4(),
            challenge_id: None,
            identity_request_id: None,
            credential: "must-not-log".into(),
        };
        let error = deliver_organization_invitation(request())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("independent Organizations runtime configuration is required"));
        assert!(!error.contains("must-not-log"));
        let _relative =
            EnvVarGuard::new("AEGAEON_ORGANIZATION_RUNTIME_CONFIG", Some("relative.json"));
        assert!(deliver_organization_invitation(request())
            .await
            .unwrap_err()
            .to_string()
            .contains("configuration is required"));
    })
}

#[path = "tests/snapshot_setup.rs"]
mod snapshot_setup;
