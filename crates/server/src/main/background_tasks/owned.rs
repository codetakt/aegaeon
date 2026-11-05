//! Retain supervisors through readiness and shutdown; never abort owned store work.
use super::*;
use crate::organizations::witness::deployment::dispatch::EnvironmentDispatcher;
use crate::runtime_configuration::DatabaseRuntimeConfiguration;
use anyhow::{anyhow, ensure, Result};
use std::time::Duration;
use tokio::{sync::oneshot, task::JoinHandle};

pub(super) struct ObservedTask {
    component: &'static str,
    ready: oneshot::Receiver<()>,
    finished: JoinHandle<Result<()>>,
}

pub(super) fn spawn<Fut>(
    restart: RuntimeRestartState,
    issuer: String,
    component: &'static str,
    task: impl FnOnce(oneshot::Sender<()>) -> Fut,
) -> ObservedTask
where
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let (ready, receiver) = oneshot::channel();
    let worker = tokio::spawn(task(ready));
    let finished = tokio::spawn(async move {
        let result = match worker.await {
            Ok(value) => value,
            Err(_) => Err(anyhow!("observed background worker failed")),
        };
        if result.is_err() || !restart.is_requested() {
            restart.request_restart(RuntimeRestartRequest::runtime_authority_unavailable(
                "observed-background",
                issuer,
                component,
            ));
            return Err(anyhow!("observed background task did not stop cleanly"));
        }
        result
    });
    ObservedTask {
        component,
        ready: receiver,
        finished,
    }
}

pub struct ObservedBackgroundTasks {
    restart: RuntimeRestartState,
    issuer: String,
    tasks: Vec<ObservedTask>,
}

impl ObservedBackgroundTasks {
    /// Start all mandatory monitors and await their initial owned work.
    ///
    /// # Errors
    /// Refuses scope/configuration mismatch, failed initial work or readiness timeout.
    pub async fn start(
        state: &AppState,
        configuration: &DatabaseRuntimeConfiguration,
        dispatcher: EnvironmentDispatcher,
        cleanup_interval: u64,
        monitor_interval: u64,
    ) -> Result<Self> {
        ensure!(!state.runtime_restart.is_requested(), "runtime is stopping");
        let mut group = Self {
            restart: state.runtime_restart.clone(),
            issuer: configuration.issuer_host.clone(),
            tasks: Vec::with_capacity(3),
        };
        let started = async {
            group.tasks.push(cleanup::spawn_observed_cleanup_task(
                state,
                dispatcher.clone(),
                cleanup_interval,
            )?);
            group
                .tasks
                .push(runtime_config::spawn_observed_runtime_config_monitor_task(
                    state,
                    configuration,
                    dispatcher.clone(),
                    monitor_interval,
                )?);
            group.tasks.push(
                runtime_config::spawn_observed_runtime_authority_notification_listener_task(
                    state,
                    configuration,
                    dispatcher,
                )?,
            );
            // One shared startup deadline includes all initial actual work and LISTEN setup.
            tokio::time::timeout(Duration::from_secs(45), async {
                for task in &mut group.tasks {
                    (&mut task.ready)
                        .await
                        .map_err(|_| anyhow!("initial {} work failed", task.component))?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .map_err(|_| anyhow!("background startup deadline"))??;
            ensure!(
                !group.restart.is_requested(),
                "background startup requested restart"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = started {
            group.stop();
            let _ = group.drain().await;
            return Err(error);
        }
        Ok(group)
    }

    fn stop(&self) {
        self.restart
            .request_restart(RuntimeRestartRequest::runtime_authority_unavailable(
                "observed-background-owner",
                self.issuer.clone(),
                "background_owner_closed",
            ));
    }

    /// The serving owner first closes admission and requests shutdown/restart.
    /// A timeout/error preserves uncertainty; it never aborts a store worker.
    ///
    /// # Errors
    /// Refuses missing shutdown intent, worker failure or incomplete drainage.
    pub async fn drain(mut self) -> Result<()> {
        ensure!(
            self.restart.is_requested(),
            "request runtime shutdown before draining"
        );
        let result = tokio::time::timeout(Duration::from_secs(45), async {
            let mut failed = false;
            for task in &mut self.tasks {
                failed |= !matches!((&mut task.finished).await, Ok(Ok(())));
            }
            ensure!(!failed, "background completion is uncertain");
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(|_| anyhow!("background shutdown deadline"))?;
        self.tasks.clear();
        result
    }
}

impl Drop for ObservedBackgroundTasks {
    fn drop(&mut self) {
        if !self.tasks.is_empty() {
            self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn organization_background_drain_retains_inflight_worker() -> Result<()> {
        let restart = RuntimeRestartState::new();
        let (finish, waiting) = oneshot::channel();
        let mut task = spawn(
            restart.clone(),
            "issuer.example".into(),
            "controlled",
            |ready| {
                Box::pin(async move {
                    let _ = ready.send(());
                    waiting.await?;
                    Ok(())
                })
            },
        );
        (&mut task.ready).await?;
        let group = ObservedBackgroundTasks {
            restart,
            issuer: "issuer.example".into(),
            tasks: vec![task],
        };
        group.stop();
        let mut drain = tokio::spawn(group.drain());
        ensure!(tokio::time::timeout(Duration::from_millis(20), &mut drain)
            .await
            .is_err());
        finish.send(()).map_err(|()| anyhow!("worker lost"))?;
        tokio::time::timeout(Duration::from_secs(1), drain).await???;
        Ok(())
    }

    #[tokio::test]
    async fn organization_background_worker_error_is_not_successful_drain() -> Result<()> {
        let restart = RuntimeRestartState::new();
        let task = spawn(
            restart.clone(),
            "issuer.example".into(),
            "controlled",
            |_ready| Box::pin(async { anyhow::bail!("controlled failure") }),
        );
        let group = ObservedBackgroundTasks {
            restart: restart.clone(),
            issuer: "issuer.example".into(),
            tasks: vec![task],
        };
        tokio::time::timeout(Duration::from_secs(1), restart.notified()).await?;
        ensure!(group.drain().await.is_err());
        Ok(())
    }
}
