mod mutation_sync;
mod snapshot;

use crate::client_registry::ClientRegistry;
use crate::runtime_authority::RuntimeAuthorityState;
use crate::runtime_restart::RuntimeRestartState;
use crate::web::AppState;

#[derive(Clone, Copy)]
pub(super) struct RuntimeClientMutationSync<'a> {
    pub(super) runtime_authority: &'a RuntimeAuthorityState,
    pub(super) runtime_restart: &'a RuntimeRestartState,
    pub(super) clients: &'a ClientRegistry,
}

impl<'a> RuntimeClientMutationSync<'a> {
    pub(super) fn from_state(state: &'a AppState) -> Self {
        Self {
            runtime_authority: &state.runtime_authority,
            runtime_restart: &state.runtime_restart,
            clients: state.clients.as_ref(),
        }
    }
}
