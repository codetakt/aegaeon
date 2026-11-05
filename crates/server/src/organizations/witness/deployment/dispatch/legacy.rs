use super::Target;
use crate::organizations::request_work::{Admission, CapacityClass};
use crate::organizations::witness::deployment::{connector::Connector, DeploymentId};
use crate::organizations::witness::{
    dispatch::acquire,
    work::{Execution, HttpExecution, ResponseLimit, Starter},
    Error, Result, Selection,
};
use axum::{http::Method, response::Response};
use std::{collections::BTreeMap, future::Future, sync::Arc};
use uuid::Uuid;

#[derive(Clone)]
pub struct Environment {
    pub id: Uuid,
    pub issuer: String,
    pub selection: Selection,
}

#[derive(Clone)]
pub struct Dispatcher {
    connector: Arc<Connector>,
    deployment: DeploymentId,
    selection: Selection,
    environments: Arc<BTreeMap<Uuid, Environment>>,
}

pub(in crate::organizations::witness::deployment) fn valid_selection(
    selection: &Selection,
) -> bool {
    ![selection.epoch, selection.primary, selection.token_store]
        .iter()
        .any(Uuid::is_nil)
        && [
            &selection.source_sha256,
            &selection.history_sha256,
            &selection.acceptance_sha256,
        ]
        .iter()
        .all(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

impl Dispatcher {
    pub(crate) fn primary_options(&self) -> sqlx::postgres::PgConnectOptions {
        self.connector.primary_options()
    }

    pub fn new(
        connector: Connector,
        deployment: DeploymentId,
        selection: Selection,
        environments: Vec<Environment>,
    ) -> Result<Self> {
        if !valid_selection(&selection) || environments.len() > 1024 {
            return Err(Error::Refused);
        }
        let mut registry = BTreeMap::new();
        for environment in environments {
            if environment.id.is_nil()
                || environment.issuer.is_empty()
                || environment.issuer.len() > 16_384
                || !valid_selection(&environment.selection)
                || (
                    environment.selection.primary,
                    environment.selection.token_store,
                ) != (selection.primary, selection.token_store)
                || registry.insert(environment.id, environment).is_some()
            {
                return Err(Error::Refused);
            }
        }
        Ok(Self {
            connector: Arc::new(connector),
            deployment,
            selection,
            environments: Arc::new(registry),
        })
    }

    /// Bind a server-owned Environment selector before any store work. The issuer
    /// must agree with the independent startup selection; a route cannot change it.
    pub fn environment(&self, id: Uuid, issuer: &str) -> Result<EnvironmentDispatcher> {
        let environment = self.environments.get(&id).ok_or(Error::Refused)?;
        if environment.issuer != issuer {
            return Err(Error::Refused);
        }
        Ok(EnvironmentDispatcher {
            dispatcher: self.clone(),
            environment: id,
        })
    }

    fn starter(&self, target: Target) -> Result<Start> {
        let child = match target {
            Target::Deployment => None,
            Target::Environment(environment) => Some(
                self.environments
                    .get(&environment)
                    .ok_or(Error::Refused)?
                    .clone(),
            ),
        };
        Ok(Start {
            connector: self.connector.clone(),
            deployment: self.deployment,
            selection: self.selection.clone(),
            child,
            startup_preflight: false,
        })
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
        let starter = self.starter(target)?;
        let local = acquire(class)?;
        Ok(starter.dispatch(local, operation))
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
        let starter = self.starter(target)?;
        let local = acquire(class)?;
        Ok(HttpExecution::dispatch(
            starter, local, method, limit, operation,
        ))
    }

    /// Management authentication precedes registry lookup, within this live parent.
    /// The child retains its parent's capacity, scope and actual cleanup ownership.
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
        let local = crate::organizations::request_work::async_store::current_owner()?;
        local.require_store_scope()?;
        if !local
            .deployment_parent()?
            .matches_selection(self.deployment, &self.selection)
        {
            return Err(Error::Refused);
        }
        let target = self
            .environments
            .get(&environment)
            .ok_or(Error::Refused)?
            .clone();
        let starter = ChildStart {
            connector: self.connector.clone(),
            target,
        };
        Ok(HttpExecution::dispatch(
            starter, local, method, limit, operation,
        ))
    }

    pub(crate) fn contains_environment(&self, environment: Uuid) -> bool {
        self.environments.contains_key(&environment)
    }
}

struct ChildStart {
    connector: Arc<Connector>,
    target: Environment,
}

impl Starter for ChildStart {
    fn start<T, F>(
        self,
        local: Admission,
        operation: F,
        deadline: tokio::time::Instant,
    ) -> Execution<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        Execution::from_worker(tokio::spawn(async move {
            tokio::time::timeout_at(deadline, async move {
                let child = self
                    .connector
                    .child_admitted(
                        &local,
                        self.target.id,
                        &self.target.issuer,
                        &self.target.selection,
                    )
                    .await?;
                let result = child.store_scope(operation).await?;
                child.complete().await?;
                Ok(result)
            })
            .await
            .map_err(|_| Error::Deadline)?
        }))
    }
}

struct Start {
    connector: Arc<Connector>,
    deployment: DeploymentId,
    selection: Selection,
    child: Option<Environment>,
    startup_preflight: bool,
}

impl Starter for Start {
    fn start<T, F>(
        self,
        local: Admission,
        operation: F,
        deadline: tokio::time::Instant,
    ) -> Execution<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        Execution::from_worker(tokio::spawn(async move {
            if self.startup_preflight {
                let target = self.child.as_ref().ok_or(Error::Refused)?;
                self.connector
                    .startup_preflight(&local, self.deployment, &self.selection, target, deadline)
                    .await?;
            }
            tokio::time::timeout_at(deadline, async move {
                let parent = self
                    .connector
                    .parent(local, self.deployment, &self.selection)
                    .await?;
                let result = if let Some(target) = self.child {
                    let acquired = self
                        .connector
                        .child(&parent, target.id, &target.issuer, &target.selection)
                        .await;
                    let child = match acquired {
                        Ok(child) => child,
                        Err(error) => {
                            // Confirmed refusal can drain; uncertain acquisition has
                            // closed the parent and cannot clear durable pending work.
                            let _ = parent.complete().await;
                            return Err(error);
                        }
                    };
                    let result = child.store_scope(operation).await?;
                    child.complete().await?;
                    result
                } else {
                    parent.admission().store_scope(operation).await?
                };
                parent.complete().await?;
                Ok(result)
            })
            .await
            .map_err(|_| Error::Deadline)?
        }))
    }
}

/// Fixed child scope retaining the mandatory parent protocol for every pass.
#[derive(Clone)]
pub struct EnvironmentDispatcher {
    dispatcher: Dispatcher,
    environment: Uuid,
}

impl EnvironmentDispatcher {
    /// One startup-only diagnostic pass precedes actual acquisition. The local
    /// ordinary owner is acquired before any await and stays with the detached
    /// worker through diagnostic cleanup and the existing owned startup. Both
    /// phases share the original execution deadline; dropping a waiter cannot
    /// cancel or release the worker.
    pub(crate) fn startup_preflight<T, F, Fut>(&self, operation: F) -> Result<Execution<T>>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        let mut starter = self
            .dispatcher
            .starter(Target::Environment(self.environment))?;
        starter.startup_preflight = true;
        let local = acquire(CapacityClass::Ordinary)?;
        Ok(starter.dispatch(local, operation))
    }
}
