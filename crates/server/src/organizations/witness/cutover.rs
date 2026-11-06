//! Native atomic epoch preparation; caller custody and supplier premises remain.
use super::{deployment::DeploymentControl, Scope, Selection};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use uuid::Uuid;

mod activation;
pub mod cli;
mod transaction;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Transition {
    pub operation_id: Uuid,
    pub revision: i64,
    pub selection: Selection,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Child {
    pub environment_id: Uuid,
    pub issuer: String,
    pub transition: Transition,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Stores {
    pub primary: Value,
    pub control: Value,
    pub token: Value,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub version: u8,
    pub deployment_id: Uuid,
    pub cutover_operation_id: Uuid,
    pub parent: Transition,
    pub children: Vec<Child>,
    pub stores: Stores,
}
impl Plan {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && !self.deployment_id.is_nil()
                && !self.cutover_operation_id.is_nil()
        );
        ensure!(!self.children.is_empty() && self.children.len() <= 64);
        let mut environments = BTreeSet::new();
        let mut epochs = BTreeSet::new();
        let common = &self.parent.selection;
        for transition in
            std::iter::once(&self.parent).chain(self.children.iter().map(|c| &c.transition))
        {
            let selection = &transition.selection;
            ensure!(
                !transition.operation_id.is_nil()
                    && (1..i64::MAX - 2).contains(&transition.revision)
            );
            ensure!(!selection.epoch.is_nil() && epochs.insert(selection.epoch));
            ensure!(!selection.primary.is_nil() && !selection.token_store.is_nil());
            ensure!(
                selection.primary == common.primary && selection.token_store == common.token_store
            );
            for sha in [
                &selection.source_sha256,
                &selection.history_sha256,
                &selection.acceptance_sha256,
            ] {
                ensure!(
                    sha.len() == 64
                        && sha
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                );
            }
        }
        for child in &self.children {
            ensure!(!child.environment_id.is_nil() && environments.insert(child.environment_id));
            ensure!(!child.issuer.is_empty() && child.issuer.len() <= 16_384);
        }
        Ok(())
    }
    fn scope(&self, child: &Child) -> Scope {
        Scope {
            environment_id: child.environment_id,
            deployment_id: self.deployment_id,
        }
    }
}

pub(crate) fn follows(actual: &Value, expected: &Value) -> Result<()> {
    let mut actual = actual
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("actual SQL observation absent"))?;
    let mut expected = expected
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("expected SQL observation absent"))?;
    let position = actual
        .remove("wal_position")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("actual WAL absent"))?;
    let minimum = expected
        .remove("wal_position")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("expected WAL absent"))?;
    ensure!(
        actual == expected && position >= minimum,
        "actual store continuity differs"
    );
    Ok(())
}

async fn inventory(control: &mut DeploymentControl, plan: &Plan, digest: &str) -> Result<Value> {
    Ok(control
        .environment_maintenance()?
        .value(
            sqlx::query_scalar("SELECT organization_witness.cutover_selection($1,$2,$3)")
                .bind(plan.deployment_id)
                .bind(plan.cutover_operation_id)
                .bind(digest),
        )
        .await?)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Fenced,
    Prepared,
    Active,
}

impl Stage {
    fn fields(self) -> (&'static str, i64) {
        match self {
            Self::Fenced => ("fenced", 0),
            Self::Prepared => ("prepared", 1),
            Self::Active => ("active", 2),
        }
    }
}

fn matches(state: &Value, transition: &Transition, stage: Stage) -> Result<()> {
    let selection = &transition.selection;
    let (phase, offset) = stage.fields();
    ensure!(
        state["operation_id"] == json!(transition.operation_id)
            && state["revision"] == json!(transition.revision + offset)
            && state["pending"] == 0
            && state["phase"] == phase,
        "epoch predecessor differs"
    );
    if stage != Stage::Fenced {
        ensure!(
            state["epoch"] == json!(selection.epoch)
                && state["primary_id"] == json!(selection.primary)
                && state["token_store_id"] == json!(selection.token_store)
                && state["source_sha256"] == selection.source_sha256
                && state["history_sha256"] == selection.history_sha256
                && state["acceptance_sha256"] == selection.acceptance_sha256,
            "prepared epoch selection differs"
        );
    } else {
        ensure!(
            state["epoch"] != json!(selection.epoch)
                && state["primary_id"] != json!(selection.primary)
                && state["token_store_id"] != json!(selection.token_store),
            "fresh selection required"
        );
    }
    Ok(())
}

fn complete(value: &Value, plan: &Plan, stage: Stage) -> Result<()> {
    matches(&value["parent"], &plan.parent, stage)?;
    ensure!(value["parent"]["deployment_id"] == json!(plan.deployment_id));
    let children = value["children"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("child inventory absent"))?;
    ensure!(
        children.len() == plan.children.len(),
        "complete child inventory differs"
    );
    for child in &plan.children {
        let actual: Vec<_> = children
            .iter()
            .filter(|state| state["environment_id"] == json!(child.environment_id))
            .collect();
        ensure!(
            actual.len() == 1 && actual[0]["deployment_id"] == json!(plan.deployment_id),
            "child namespace differs"
        );
        matches(actual[0], &child.transition, stage)?;
    }
    Ok(())
}
