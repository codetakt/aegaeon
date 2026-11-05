#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
mod test_clients;

use super::jwks_runtime_state::JwksRuntimeState;
#[cfg(test)]
use super::jwt_replay_store_from_env;
use super::{
    ClientAssertionRuntimePolicy, ClientRegistry, ClientRegistryInitError, JwksRuntimePolicy,
};
use crate::config::RuntimeStateNamespace;
#[cfg(test)]
use crate::middleware::InMemoryReplayStore;

impl ClientRegistry {
    /// Build an empty process-local client registry for tests.
    ///
    /// Production construction uses PostgreSQL replay decisions and shared JWKS state.
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

    pub(crate) fn from_postgres_with_runtime_policy(
        pool: sqlx::PgPool,
        client_assertion_policy: ClientAssertionRuntimePolicy,
        jwks_policy: JwksRuntimePolicy,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ClientRegistryInitError> {
        let jwks_state =
            JwksRuntimeState::from_postgres(pool.clone(), namespace, jwks_policy.clone())?;
        Ok(Self::with_replay_store_policy_and_jwks_state(
            std::sync::Arc::new(crate::middleware::replay_store::PostgresReplayStore::new(
                pool,
                namespace.replay_namespace("client-assertion-replay"),
            )),
            client_assertion_policy,
            jwks_policy,
            jwks_state,
        ))
    }

    pub(crate) async fn cleanup_replays(&self) -> Result<(), String> {
        self.jwt_replay_store
            .clone()
            .cleanup_async()
            .await
            .map_err(|err| err.to_string())
    }

    pub(crate) async fn cleanup_jwks(&self) -> Result<(), String> {
        if let Some(native) = self.jwks_state.native() {
            native.cleanup().await?;
        }
        Ok(())
    }

    #[cfg(test)]
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
