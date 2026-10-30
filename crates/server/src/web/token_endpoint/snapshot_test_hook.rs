//! Test-only pauses observe the real context path without replacing authentication.
use std::sync::Arc;
use tokio::sync::Barrier;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::web) enum Phase {
    BeforeAuthentication,
    AfterAuthentication,
}

tokio::task_local! {
    pub(in crate::web) static OBSERVATION: (Phase, Arc<Barrier>, Arc<Barrier>);
}

pub(super) async fn pause(phase: Phase) {
    let barriers = OBSERVATION
        .try_with(|(selected, observed, resume)| {
            (*selected == phase).then(|| (observed.clone(), resume.clone()))
        })
        .ok()
        .flatten();
    if let Some((observed, resume)) = barriers {
        observed.wait().await;
        resume.wait().await;
    }
}
