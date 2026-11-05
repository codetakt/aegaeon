//! Fixed deployment/Environment routing over the selected database runtime.
#[cfg(test)]
use super::{connector::Connector, DeploymentId};
#[cfg(test)]
use crate::organizations::witness::Selection;
use crate::organizations::{
    lifecycle::{runtime::CurrentStart, Runtime},
    request_work::{async_store, CapacityClass},
    witness::{
        work::{Execution, HttpExecution, ResponseLimit},
        Error, Result,
    },
};
use axum::{http::Method, response::Response};
use std::{future::Future, sync::Arc};
use uuid::Uuid;

// Retained while operator and legacy fixture migration is completed. Production
// v2 configuration only constructs Current; it never connects a control store.
#[cfg(test)]
mod legacy;
#[cfg(test)]
pub(super) use legacy::valid_selection;
#[cfg(test)]
pub use legacy::Environment;
#[derive(Clone, Copy)]
pub enum Target {
    Deployment,
    Environment(Uuid),
}

#[derive(Clone)]
pub struct Dispatcher(Backend);
#[derive(Clone)]
enum Backend {
    Current(Arc<Runtime>),
    #[cfg(test)]
    Legacy(legacy::Dispatcher),
}
impl Dispatcher {
    pub(crate) async fn close(&self) {
        match &self.0 {
            Backend::Current(runtime) => runtime.close().await,
            #[cfg(test)]
            Backend::Legacy(_) => (),
        }
    }
    pub fn current(runtime: Arc<Runtime>) -> Self {
        Self(Backend::Current(runtime))
    }
    #[cfg(test)]
    pub fn new(
        connector: Connector,
        deployment: DeploymentId,
        selection: Selection,
        environments: Vec<Environment>,
    ) -> Result<Self> {
        Ok(Self(Backend::Legacy(legacy::Dispatcher::new(
            connector,
            deployment,
            selection,
            environments,
        )?)))
    }
    pub(crate) fn primary_options(&self) -> sqlx::postgres::PgConnectOptions {
        match &self.0 {
            Backend::Current(runtime) => runtime.pool().connect_options().as_ref().clone(),
            #[cfg(test)]
            Backend::Legacy(old) => old.primary_options(),
        }
    }
    pub fn environment(&self, id: Uuid, issuer: &str) -> Result<EnvironmentDispatcher> {
        match &self.0 {
            Backend::Current(runtime)
                if runtime
                    .environments
                    .get(&id)
                    .is_some_and(|value| value == issuer) => {}
            Backend::Current(_) => return Err(Error::Refused),
            #[cfg(test)]
            Backend::Legacy(old) => {
                old.environment(id, issuer)?;
            }
        }
        Ok(EnvironmentDispatcher {
            dispatcher: self.clone(),
            environment: id,
            #[cfg(test)]
            issuer: issuer.into(),
        })
    }
    pub(crate) fn contains_environment(&self, id: Uuid) -> bool {
        match &self.0 {
            Backend::Current(runtime) => runtime.environments.contains_key(&id),
            #[cfg(test)]
            Backend::Legacy(old) => old.contains_environment(id),
        }
    }
    pub fn start<T, F, Fut>(
        &self,
        target: Target,
        class: CapacityClass,
        operation: F,
    ) -> Result<Execution<T>>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        if class == CapacityClass::Snapshot {
            return Err(Error::Refused);
        }
        match &self.0 {
            Backend::Current(runtime) => runtime.start(environment(target), class, operation),
            #[cfg(test)]
            Backend::Legacy(old) => old.start(target, class, operation),
        }
    }
    pub fn start_http<F, Fut>(
        &self,
        target: Target,
        class: CapacityClass,
        method: Method,
        operation: F,
    ) -> Result<HttpExecution>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        self.start_serving_http(
            target,
            class,
            method,
            ResponseLimit::Organization,
            operation,
        )
    }
    pub(crate) fn start_serving_http<F, Fut>(
        &self,
        target: Target,
        class: CapacityClass,
        method: Method,
        limit: ResponseLimit,
        operation: F,
    ) -> Result<HttpExecution>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        match &self.0 {
            Backend::Current(runtime) => Ok(HttpExecution::dispatch(
                CurrentStart,
                runtime.admit(class, environment(target))?,
                method,
                limit,
                operation,
            )),
            #[cfg(test)]
            Backend::Legacy(old) => old.start_serving_http(target, class, method, limit, operation),
        }
    }
    pub(crate) fn start_child_http<F, Fut>(
        &self,
        environment: Uuid,
        method: Method,
        limit: ResponseLimit,
        operation: F,
    ) -> Result<HttpExecution>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        match &self.0 {
            Backend::Current(runtime) => {
                let child = async_store::current_owner()?.runtime_child(runtime, environment)?;
                Ok(HttpExecution::dispatch(
                    CurrentStart,
                    child,
                    method,
                    limit,
                    operation,
                ))
            }
            #[cfg(test)]
            Backend::Legacy(old) => old.start_child_http(environment, method, limit, operation),
        }
    }
}
fn environment(target: Target) -> Option<Uuid> {
    match target {
        Target::Deployment => None,
        Target::Environment(id) => Some(id),
    }
}
#[derive(Clone)]
pub struct EnvironmentDispatcher {
    dispatcher: Dispatcher,
    environment: Uuid,
    #[cfg(test)]
    issuer: String,
}
impl EnvironmentDispatcher {
    pub(crate) fn deployment(&self) -> Dispatcher {
        self.dispatcher.clone()
    }
    pub(crate) fn primary_options(&self) -> sqlx::postgres::PgConnectOptions {
        self.dispatcher.primary_options()
    }
    pub fn environment_id(&self) -> Uuid {
        self.environment
    }
    pub(crate) fn startup_preflight<T, F, Fut>(&self, operation: F) -> Result<Execution<T>>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        match &self.dispatcher.0 {
            Backend::Current(runtime) => {
                runtime.start(Some(self.environment), CapacityClass::Ordinary, operation)
            }
            #[cfg(test)]
            Backend::Legacy(old) => old
                .environment(self.environment, &self.issuer)?
                .startup_preflight(operation),
        }
    }
    pub fn start<T, F, Fut>(&self, class: CapacityClass, operation: F) -> Result<Execution<T>>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        self.dispatcher
            .start(Target::Environment(self.environment), class, operation)
    }
    pub async fn run_periodic<F, Fut>(
        &self,
        interval_secs: u64,
        restart: crate::runtime_restart::RuntimeRestartState,
        operation: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        crate::organizations::witness::dispatch::periodic::run(interval_secs, restart, || {
            self.start(CapacityClass::Ordinary, operation.clone())
        })
        .await
    }
}
