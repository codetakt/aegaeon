//! Parent-owned, bounded logout delivery state. No background sends or exactly-once claim.
use serde::{Deserialize, Serialize};

mod transition;
mod validation;
pub(crate) use transition::transition;

pub(crate) const VERSION: &str = "1";
pub(crate) const STORAGE_ERROR: &str = "OIDC logout delivery storage unavailable or invalid";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub sid: String,
    pub event_jti: String,
    pub subject: String,
    pub client_id: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub issuer: String,
    pub uri: String,
    pub session_required: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Candidate {
    pub token: String,
    pub token_jti: String,
    pub iat: u64,
    pub exp: u64,
    pub digest: String,
}

impl Candidate {
    pub(crate) fn new(token: String, token_jti: String, iat: u64, exp: u64) -> Self {
        let digest = validation::digest(&token);
        Self {
            token,
            token_jti,
            iat,
            exp,
            digest,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Permit {
    pub owner: String,
    pub attempt: u8,
    pub deadline: u64,
    pub horizon: u64,
    pub checked_at: u64,
    pub token: String,
    pub retention_deadline: Option<std::time::Instant>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
pub(crate) enum Phase {
    InFlight { owner: String, deadline: u64 },
    Retry { due: u64 },
    Delivered,
    Terminal,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub identity: Identity,
    pub binding: Option<Binding>,
    pub candidate: Option<Candidate>,
    pub phase: Phase,
    pub attempts: u8,
    pub observed_at: u64,
}

#[derive(Clone)]
pub(crate) enum Completion {
    Delivered,
    Terminal,
    Recoverable { retry_after: Option<u64> },
}

#[derive(Clone)]
pub(crate) enum Command {
    Probe,
    Claim {
        candidate: Option<Candidate>,
        owner: String,
        timeout: u64,
    },
    Check(Permit),
    Complete(Permit, Completion),
}

#[derive(Clone)]
pub(crate) struct Request {
    pub identity: Identity,
    pub binding: Option<Binding>,
    pub command: Command,
    #[cfg(test)]
    pub test_now: Option<u64>,
    #[cfg(test)]
    pub before_cas: Option<std::sync::Arc<std::sync::Barrier>>,
}

impl Request {
    pub(crate) fn new(identity: Identity, binding: Option<Binding>, command: Command) -> Self {
        Self {
            identity,
            binding,
            command,
            #[cfg(test)]
            test_now: None,
            #[cfg(test)]
            before_cas: None,
        }
    }

    pub(crate) fn time_override(&self) -> Option<u64> {
        #[cfg(test)]
        {
            self.test_now
        }
        #[cfg(not(test))]
        {
            None
        }
    }
}

pub(crate) enum Outcome {
    Ready { needs_candidate: bool },
    Granted(Permit),
    AlreadyDelivered,
    Completed,
    Deferred,
    Terminal,
    LegacyUnknown,
    Missing,
}

pub(crate) struct Parent {
    pub user_id: String,
    pub event_jti: String,
    pub logged_out_at: u64,
    pub deadline: u64,
}

pub(crate) struct Transition {
    pub record: Option<String>,
    pub outcome: Outcome,
    // Rechecked atomically with the current parent and prior record, even for a read-only preflight.
    pub valid_before: u64,
}

pub(crate) fn recipient_field(client: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let mut hash = aegaeon_crypto::hash::Sha256Hasher::new();
    hash.update(b"aegaeon:oidc-logout-session:delivery:v1");
    hash.update(&(client.len() as u64).to_be_bytes());
    hash.update(client.as_bytes());
    format!("delivery:{}", URL_SAFE_NO_PAD.encode(hash.finalize()))
}
