use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeStateNamespace {
    environment_id: Arc<str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeRedisAtomicGroup {
    AuthorizationCodeGrant,
}

impl RuntimeRedisAtomicGroup {
    const fn label(self) -> &'static str {
        match self {
            Self::AuthorizationCodeGrant => "authorization-code-grant",
        }
    }
}

impl RuntimeStateNamespace {
    /// Restored continuations cannot enter a newly activated runtime namespace.
    /// The caller must obtain this generation from checked lifecycle selection.
    #[must_use]
    pub(crate) fn from_generation(environment_id: Uuid, generation: Uuid) -> Self {
        Self {
            environment_id: format!("{environment_id}:generation:{generation}").into(),
        }
    }

    #[must_use]
    pub fn from_environment_id(environment_id: Uuid) -> Self {
        Self {
            environment_id: Arc::from(environment_id.to_string().into_boxed_str()),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn for_tests(value: impl Into<Arc<str>>) -> Self {
        Self {
            environment_id: value.into(),
        }
    }

    #[must_use]
    pub fn redis_prefix(&self, surface: &str, version: &str) -> String {
        format!(
            "aegaeon:{{runtime:{}:surface:{surface}}}:{version}",
            self.environment_id
        )
    }

    #[must_use]
    pub fn redis_atomic_group_prefix(
        &self,
        group: RuntimeRedisAtomicGroup,
        surface: &str,
        version: &str,
    ) -> String {
        format!(
            "aegaeon:{{runtime:{}:atomic:{}}}:{surface}:{version}",
            self.environment_id,
            group.label()
        )
    }

    #[must_use]
    pub fn replay_namespace(&self, surface: &str) -> String {
        format!("runtime:{}:{surface}", self.environment_id)
    }

    #[must_use]
    pub fn flow_namespace(&self, surface: &str, flow: &str) -> String {
        format!("runtime:{}:{surface}:{flow}", self.environment_id)
    }
}

#[cfg(test)]
mod tests;
