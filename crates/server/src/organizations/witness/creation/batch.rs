//! A finite, all-or-none SQL statement; no loop of independently committed RPCs.
use super::*;
use serde_json::{json, Value};
use std::collections::HashSet;

pub(crate) const MAX_BATCH: usize = 100;

pub(crate) fn validate_batch(inputs: &[Input]) -> Result<()> {
    if inputs.is_empty() || inputs.len() > MAX_BATCH {
        return Err(Error::Refused);
    }
    let mut selectors = HashSet::new();
    let mut subjects = HashSet::new();
    for input in inputs {
        if input.kind != Kind::ManagementCsv
            || input.actor != inputs[0].actor
            || !selectors.insert(input.selector)
            || input.subject.as_deref().is_none_or(|s| !subjects.insert(s))
        {
            return Err(Error::Refused);
        }
    }
    Ok(())
}

impl Control {
    pub async fn prepare_creation_batch(
        &mut self,
        admission: &Admission,
        inputs: &[Input],
    ) -> Result<Vec<Receipt>> {
        if self.role != Role::Runtime {
            return Err(Error::Refused);
        }
        validate_batch(inputs)?;
        let rows: Vec<Value> = inputs
            .iter()
            .map(|input| {
                json!({
                    "kind": input.kind.as_str(), "selector": history::hex(&input.selector),
                    "actor": history::hex(&input.actor), "payload": history::hex(&input.payload),
                    "subject": input.subject,
                })
            })
            .collect();
        let value = self.value(sqlx::query_scalar(
            "SELECT jsonb_agg(organization_witness.creation_prepare($1,$2,$3,$4,$5,$6,row->>'kind',row->>'selector',row->>'actor',row->>'payload',row->>'subject') ORDER BY ordinal) FROM jsonb_array_elements($7::jsonb) WITH ORDINALITY AS input(row,ordinal)"
        ).bind(admission.scope.environment_id).bind(admission.scope.deployment_id)
            .bind(admission.slot.slot).bind(admission.slot.generation).bind(admission.slot.epoch)
            .bind(admission.slot.worker_id).bind(Value::Array(rows))).await?;
        let values = value.as_array().ok_or(Error::Refused)?;
        if values.len() != inputs.len() {
            return Err(Error::Refused);
        }
        let mut operations = HashSet::new();
        let mut owners = HashSet::new();
        values
            .iter()
            .zip(inputs)
            .map(|(value, input)| {
                let receipt = Receipt::parse(value.clone(), admission)?;
                if !receipt.matches(input)
                    || receipt.state() == State::Retryable
                    || !operations.insert(receipt.operation_id())
                    || !owners.insert(receipt.owner_id())
                {
                    return Err(Error::Refused);
                }
                if receipt.state() == State::Reserved {
                    receipt.owner(admission)?;
                }
                Ok(receipt)
            })
            .collect()
    }

    pub async fn finish_creation_batch(
        &mut self,
        admission: &Admission,
        receipts: &[Receipt],
        outcomes: &[PrimaryOutcome],
    ) -> Result<Vec<Receipt>> {
        if self.role != Role::Runtime
            || receipts.is_empty()
            || receipts.len() > MAX_BATCH
            || receipts.len() != outcomes.len()
        {
            return Err(Error::Refused);
        }
        let mut ids = HashSet::new();
        let committed = outcomes[0].receipt.is_some();
        let mut rows = Vec::with_capacity(receipts.len());
        for (receipt, outcome) in receipts.iter().zip(outcomes) {
            receipt.validate_finish(admission, outcome)?;
            if receipt.0.kind != Kind::ManagementCsv
                || !ids.insert(receipt.operation_id())
                || outcome.receipt.is_some() != committed
            {
                return Err(Error::Refused);
            }
            rows.push(
                json!({"operation":receipt.operation_id(),"attempt":receipt.attempt(),
                "state":if committed {"committed"} else {"retryable"},
                "digest":outcome.receipt.as_ref().map(history::hex)}),
            );
        }
        let value = self.value(sqlx::query_scalar(
            "SELECT jsonb_agg(organization_witness.creation_finish($1,$2,$3,$4,$5,$6,(row->>'operation')::uuid,(row->>'attempt')::integer,row->>'state',row->>'digest') ORDER BY ordinal) FROM jsonb_array_elements($7::jsonb) WITH ORDINALITY AS input(row,ordinal)"
        ).bind(admission.scope.environment_id).bind(admission.scope.deployment_id)
            .bind(admission.slot.slot).bind(admission.slot.generation).bind(admission.slot.epoch)
            .bind(admission.slot.worker_id).bind(Value::Array(rows))).await?;
        let values = value.as_array().ok_or(Error::Refused)?;
        if values.len() != receipts.len() {
            return Err(Error::Refused);
        }
        values
            .iter()
            .zip(receipts)
            .zip(outcomes)
            .map(|((value, before), outcome)| {
                let receipt = Receipt::parse(value.clone(), admission)?;
                receipt.owner(admission)?;
                let a = &receipt.0;
                let b = &before.0;
                if a.operation_id != b.operation_id
                    || a.attempt != b.attempt
                    || a.kind != b.kind
                    || a.selector_sha256 != b.selector_sha256
                    || a.actor_sha256 != b.actor_sha256
                    || a.payload_sha256 != b.payload_sha256
                    || a.requested_subject != b.requested_subject
                    || a.owner_id != b.owner_id
                    || a.subject != b.subject
                    || a.state
                        != if committed {
                            State::Committed
                        } else {
                            State::Retryable
                        }
                    || a.receipt_sha256 != outcome.receipt.as_ref().map(history::hex)
                {
                    return Err(Error::Refused);
                }
                Ok(receipt)
            })
            .collect()
    }
}
