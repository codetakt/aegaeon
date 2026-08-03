#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
mod test_clients;

use super::jwks_runtime_state::JwksRuntimeState;
use super::{
    jwt_replay_store_from_env, ClientAssertionRuntimePolicy, ClientRegistry,
    ClientRegistryInitError, JwksRuntimePolicy,
};
use crate::config::RuntimeStateNamespace;
#[cfg(test)]
use crate::middleware::InMemoryReplayStore;

impl ClientRegistry {
    /// Build an empty process-local client registry for tests.
    ///
    /// Production code should use [`Self::from_shared_store_env_with_runtime_policy`] so shared
    /// replay and JWKS runtime state are backed by shared stores.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::with_replay_store_and_policy(
            Arc::new(InMemoryReplayStore::new()),
            ClientAssertionRuntimePolicy::default(),
            JwksRuntimePolicy::default(),
        )
    }

    /// Build an empty process-local client registry with explicit runtime policy for tests.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_with_runtime_policy_for_tests(
        client_assertion_policy: ClientAssertionRuntimePolicy,
        jwks_policy: JwksRuntimePolicy,
    ) -> Self {
        Self::with_replay_store_policy_and_jwks_state(
            Arc::new(InMemoryReplayStore::new()),
            client_assertion_policy,
            jwks_policy,
            JwksRuntimeState::default(),
        )
    }

    pub fn from_shared_store_env_with_runtime_policy(
        client_assertion_policy: ClientAssertionRuntimePolicy,
        jwks_policy: JwksRuntimePolicy,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ClientRegistryInitError> {
        // Assertion/JWKS policy may be database-authoritative. Keep this constructor limited to
        // shared runtime stores and JWKS runtime state bootstrap.
        let jwks_state = JwksRuntimeState::try_from_env(runtime_state_namespace)?;
        jwt_replay_store_from_env(runtime_state_namespace).map(|store| {
            Self::with_replay_store_policy_and_jwks_state(
                store,
                client_assertion_policy,
                jwks_policy,
                jwks_state,
            )
        })
    }
}
