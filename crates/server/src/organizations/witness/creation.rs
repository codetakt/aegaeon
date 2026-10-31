//! Retained allocation is not primary commit evidence or caller authorization.
use super::{history, Admission, Control, Error, Result, Role};
use serde::Deserialize;
use uuid::Uuid;

pub(crate) mod primary;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    ManagementCreate,
    ManagementInvite,
    ManagementCsv,
    Registration,
    Upstream,
}
impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ManagementCreate => "management_create",
            Self::ManagementInvite => "management_invite",
            Self::ManagementCsv => "management_csv",
            Self::Registration => "registration",
            Self::Upstream => "upstream",
        }
    }
}

/// Bounded transport of caller-established canonical bindings. This constructor
/// validates shape only; authentication and canonical input construction remain
/// obligations of the actual creation caller.
#[derive(Clone)]
pub struct Input {
    kind: Kind,
    selector: [u8; 32],
    actor: [u8; 32],
    payload: [u8; 32],
    subject: Option<String>,
}
impl Input {
    pub fn new(
        kind: Kind,
        selector: [u8; 32],
        actor: [u8; 32],
        payload: [u8; 32],
        subject: Option<&str>,
    ) -> Result<Self> {
        if let Some(subject) = subject {
            history::validate_subject(subject)?;
        }
        Ok(Self {
            kind,
            selector,
            actor,
            payload,
            subject: subject.map(str::to_owned),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Reserved,
    Retryable,
    Committed,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    environment_id: Uuid,
    operation_id: Uuid,
    kind: Kind,
    selector_sha256: String,
    actor_sha256: String,
    payload_sha256: String,
    requested_subject: Option<String>,
    owner_id: Uuid,
    subject: String,
    state: State,
    attempt: u32,
    epoch: Uuid,
    slot: i32,
    generation: i64,
    worker_id: Uuid,
    principal: String,
    receipt_sha256: Option<String>,
}

/// Only an authenticated fixed-function response creates this value. It cannot
/// be deserialized by callers or reconstructed from an HTTP body.
#[derive(Clone, Debug)]
pub struct Receipt(Stored);
impl Receipt {
    fn matches(&self, input: &Input) -> bool {
        self.0.kind == input.kind
            && self.0.selector_sha256 == history::hex(&input.selector)
            && self.0.actor_sha256 == history::hex(&input.actor)
            && self.0.payload_sha256 == history::hex(&input.payload)
            && self.0.requested_subject == input.subject
    }
    pub fn owner_id(&self) -> Uuid {
        self.0.owner_id
    }
    pub fn subject(&self) -> &str {
        &self.0.subject
    }
    pub fn operation_id(&self) -> Uuid {
        self.0.operation_id
    }
    pub fn attempt(&self) -> u32 {
        self.0.attempt
    }
    pub fn state(&self) -> State {
        self.0.state
    }

    fn owner(&self, admission: &Admission) -> Result<()> {
        let row = &self.0;
        if row.environment_id != admission.scope.environment_id
            || row.epoch != admission.slot.epoch
            || row.slot != admission.slot.slot
            || row.generation != admission.slot.generation
            || row.worker_id != admission.slot.worker_id
            || row.principal != admission.slot.principal
        {
            return Err(Error::Refused);
        }
        Ok(())
    }

    pub(in crate::organizations) fn validate_finish(
        &self,
        admission: &Admission,
        outcome: &PrimaryOutcome,
    ) -> Result<()> {
        if outcome.operation_id != self.operation_id() || outcome.attempt != self.attempt() {
            return Err(Error::Refused);
        }
        self.owner(admission)
    }

    fn parse(value: serde_json::Value, admission: &Admission) -> Result<Self> {
        let row: Stored = serde_json::from_value(value)?;
        history::validate_subject(&row.subject)?;
        if let Some(subject) = &row.requested_subject {
            history::validate_subject(subject)?;
            if subject != &row.subject {
                return Err(Error::Refused);
            }
        } else if row.subject != row.owner_id.to_string() {
            return Err(Error::Refused);
        }
        let hash = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        };
        if row.environment_id != admission.scope.environment_id
            || row.operation_id.is_nil()
            || row.owner_id.is_nil()
            || row.epoch.is_nil()
            || row.worker_id.is_nil()
            || !(1..=32).contains(&row.attempt)
            || !(0..64).contains(&row.slot)
            || row.generation <= 0
            || row.principal.is_empty()
            || row.principal.len() > 63
            || row.principal.contains('\0')
            || !hash(&row.selector_sha256)
            || !hash(&row.actor_sha256)
            || !hash(&row.payload_sha256)
            || (row.state == State::Committed) != row.receipt_sha256.is_some()
            || row
                .receipt_sha256
                .as_deref()
                .is_some_and(|value| !hash(value))
        {
            return Err(Error::Refused);
        }
        Ok(Self(row))
    }
}

/// Opaque primary-outcome evidence. A production constructor must live beside
/// the owned primary transaction/immutable receipt integration; no general
/// boolean, serialized claim or public constructor can manufacture it.
#[derive(Clone)]
pub struct PrimaryOutcome {
    operation_id: Uuid,
    attempt: u32,
    receipt: Option<[u8; 32]>,
}
impl PrimaryOutcome {
    #[cfg(test)]
    pub(in crate::organizations) fn for_test(
        receipt: &Receipt,
        committed: Option<[u8; 32]>,
    ) -> Self {
        Self {
            operation_id: receipt.operation_id(),
            attempt: receipt.attempt(),
            receipt: committed,
        }
    }
}

impl Control {
    pub async fn prepare_creation(
        &mut self,
        admission: &Admission,
        input: &Input,
    ) -> Result<Receipt> {
        if self.role != Role::Runtime {
            return Err(Error::Refused);
        }
        let value = self.value(sqlx::query_scalar("SELECT organization_witness.creation_prepare($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(admission.scope.environment_id).bind(admission.scope.deployment_id)
            .bind(admission.slot.slot).bind(admission.slot.generation).bind(admission.slot.epoch).bind(admission.slot.worker_id)
            .bind(input.kind.as_str()).bind(history::hex(&input.selector)).bind(history::hex(&input.actor))
            .bind(history::hex(&input.payload)).bind(input.subject.as_deref())).await?;
        let result = Receipt::parse(value, admission)?;
        let row = &result.0;
        if row.kind != input.kind
            || row.selector_sha256 != history::hex(&input.selector)
            || row.actor_sha256 != history::hex(&input.actor)
            || row.payload_sha256 != history::hex(&input.payload)
            || row.requested_subject != input.subject
            || row.state == State::Retryable
        {
            return Err(Error::Refused);
        }
        if row.state == State::Reserved {
            result.owner(admission)?;
        }
        Ok(result)
    }

    pub async fn finish_creation(
        &mut self,
        admission: &Admission,
        receipt: &Receipt,
        outcome: &PrimaryOutcome,
    ) -> Result<Receipt> {
        if self.role != Role::Runtime {
            return Err(Error::Refused);
        }
        receipt.validate_finish(admission, outcome)?;
        let state = if outcome.receipt.is_some() {
            State::Committed
        } else {
            State::Retryable
        };
        let digest = outcome.receipt.as_ref().map(history::hex);
        let value = self
            .value(
                sqlx::query_scalar(
                    "SELECT organization_witness.creation_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                )
                .bind(admission.scope.environment_id)
                .bind(admission.scope.deployment_id)
                .bind(admission.slot.slot)
                .bind(admission.slot.generation)
                .bind(admission.slot.epoch)
                .bind(admission.slot.worker_id)
                .bind(receipt.operation_id())
                .bind(i32::try_from(receipt.attempt()).map_err(|_| Error::Refused)?)
                .bind(if state == State::Committed {
                    "committed"
                } else {
                    "retryable"
                })
                .bind(digest.as_deref()),
            )
            .await?;
        let result = Receipt::parse(value, admission)?;
        result.owner(admission)?;
        let before = &receipt.0;
        let after = &result.0;
        if after.operation_id != before.operation_id
            || after.attempt != before.attempt
            || after.kind != before.kind
            || after.selector_sha256 != before.selector_sha256
            || after.actor_sha256 != before.actor_sha256
            || after.payload_sha256 != before.payload_sha256
            || after.requested_subject != before.requested_subject
            || after.owner_id != before.owner_id
            || after.subject != before.subject
            || after.state != state
            || after.receipt_sha256 != digest
        {
            return Err(Error::Refused);
        }
        Ok(result)
    }
}
