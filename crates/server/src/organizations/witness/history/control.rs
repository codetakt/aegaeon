use super::*;
use crate::organizations::witness::{Admission, Control, Scope};
use serde::Deserialize;

/// Observation only; serialized progress does not authorize history or serving.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    pub environment_id: Uuid,
    pub issuer_host: String,
    pub operation_id: Uuid,
    pub control_revision: i64,
    pub receipt_id: Uuid,
    pub manifest_sha256: String,
    pub inventory_sha256: String,
    pub expected_owners: u32,
    pub expected_subjects: u32,
    pub expected_digest: String,
    pub sequence: u64,
    pub owner_count: u32,
    pub subject_count: u32,
    pub digest: String,
    pub sealed: bool,
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(value: &str) -> Result<[u8; 32]> {
    if !hash(value) {
        return Err(refused());
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| refused())?;
    }
    Ok(result)
}
impl Progress {
    fn validate(&self, scope: Scope) -> Result<()> {
        if self.environment_id != scope.environment_id
            || initial_digest(self.environment_id, &self.issuer_host).is_err()
            || self.operation_id.is_nil()
            || self.control_revision <= 0
            || u64::from(self.expected_owners) + u64::from(self.expected_subjects)
                > MAX_ENTRIES as u64
            || self.sequence > MAX_ENTRIES as u64
            || self.sequence != u64::from(self.owner_count) + u64::from(self.subject_count)
            || !hash(&self.manifest_sha256)
            || !hash(&self.inventory_sha256)
            || !hash(&self.expected_digest)
            || !hash(&self.digest)
        {
            return Err(refused());
        }
        Ok(())
    }
}
fn progress(value: serde_json::Value, scope: Scope) -> Result<Progress> {
    let result: Progress = serde_json::from_value(value)?;
    result.validate(scope)?;
    Ok(result)
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredEntry {
    pub sequence: u64,
    pub kind: String,
    pub owner_id: Uuid,
    pub subject: Option<String>,
    pub operation_id: Uuid,
    pub epoch: Option<Uuid>,
    pub worker_id: Option<Uuid>,
    pub slot: Option<i32>,
    pub generation: Option<i64>,
    pub principal: String,
    pub recorded_at: String,
    pub previous_digest: String,
    pub digest: String,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub progress: Progress,
    pub entries: Vec<StoredEntry>,
}

impl Control {
    pub async fn history_begin(
        &mut self,
        scope: Scope,
        operation: Uuid,
        revision: i64,
        plan: &Plan,
    ) -> Result<Progress> {
        self.maintenance()?;
        if plan.environment_id != scope.environment_id {
            return Err(refused());
        }
        let (owners, subjects) = plan.counts();
        let result = progress(
            self.value(
                sqlx::query_scalar(
                    "SELECT organization_witness.history_begin($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                )
                .bind(scope.environment_id)
                .bind(scope.deployment_id)
                .bind(operation)
                .bind(revision)
                .bind(&plan.issuer_host)
                .bind(plan.receipt_id)
                .bind(&plan.manifest_sha256)
                .bind(&plan.inventory_sha256)
                .bind(i32::try_from(owners).map_err(|_| refused())?)
                .bind(i32::try_from(subjects).map_err(|_| refused())?)
                .bind(plan.digest()),
            )
            .await?,
            scope,
        )?;
        if result.issuer_host != plan.issuer_host
            || result.operation_id != operation
            || result.control_revision != revision
            || result.receipt_id != plan.receipt_id
            || result.manifest_sha256 != plan.manifest_sha256
            || result.inventory_sha256 != plan.inventory_sha256
            || result.expected_owners as usize != owners
            || result.expected_subjects as usize != subjects
            || result.expected_digest != plan.digest()
        {
            return Err(refused());
        }
        Ok(result)
    }

    pub async fn history_batch(
        &mut self,
        scope: Scope,
        operation: Uuid,
        revision: i64,
        from: u64,
        entries: &[Entry],
    ) -> Result<Progress> {
        self.maintenance()?;
        aegaeon_pure::organization_history::batch_end(
            from,
            u64::try_from(entries.len()).map_err(|_| refused())?,
        )
        .ok_or_else(refused)?;
        let encoded = serde_json::to_value(entries)?;
        if serde_json::to_vec(&encoded)?.len() > 1024 * 1024 {
            return Err(refused());
        }
        progress(
            self.value(
                sqlx::query_scalar("SELECT organization_witness.history_batch($1,$2,$3,$4,$5,$6)")
                    .bind(scope.environment_id)
                    .bind(scope.deployment_id)
                    .bind(operation)
                    .bind(revision)
                    .bind(i64::try_from(from).map_err(|_| refused())?)
                    .bind(encoded),
            )
            .await?,
            scope,
        )
    }

    pub async fn history_seal(
        &mut self,
        scope: Scope,
        operation: Uuid,
        revision: i64,
    ) -> Result<Progress> {
        self.maintenance()?;
        let result = progress(
            self.value(
                sqlx::query_scalar("SELECT organization_witness.history_seal($1,$2,$3,$4)")
                    .bind(scope.environment_id)
                    .bind(scope.deployment_id)
                    .bind(operation)
                    .bind(revision),
            )
            .await?,
            scope,
        )?;
        if !result.sealed
            || result.owner_count != result.expected_owners
            || result.subject_count != result.expected_subjects
            || result.digest != result.expected_digest
        {
            return Err(refused());
        }
        Ok(result)
    }

    pub async fn history_read(
        &mut self,
        scope: Scope,
        operation: Uuid,
        revision: i64,
        after: u64,
        limit: u32,
    ) -> Result<Page> {
        self.maintenance()?;
        if after > MAX_ENTRIES as u64 || limit == 0 || limit > BATCH_ENTRIES as u32 {
            return Err(refused());
        }
        let page: Page = serde_json::from_value(
            self.value(
                sqlx::query_scalar("SELECT organization_witness.history_read($1,$2,$3,$4,$5,$6)")
                    .bind(scope.environment_id)
                    .bind(scope.deployment_id)
                    .bind(operation)
                    .bind(revision)
                    .bind(i64::try_from(after).map_err(|_| refused())?)
                    .bind(i32::try_from(limit).map_err(|_| refused())?),
            )
            .await?,
        )?;
        page.progress.validate(scope)?;
        let expected = aegaeon_pure::organization_history::page_length(
            page.progress.sequence,
            after,
            u64::from(limit),
        )
        .ok_or_else(refused)?;
        if page.entries.len() as u64 != expected {
            return Err(refused());
        }
        let mut preceding = if after == 0 {
            Some(initial_digest(
                scope.environment_id,
                &page.progress.issuer_host,
            )?)
        } else {
            None
        };
        for (index, entry) in page.entries.iter().enumerate() {
            if entry.sequence != after + index as u64 + 1
                || !hash(&entry.digest)
                || !hash(&entry.previous_digest)
                || entry.operation_id.is_nil()
                || entry.principal.is_empty()
                || entry.principal.len() > 63
                || time::OffsetDateTime::parse(
                    &entry.recorded_at,
                    &time::format_description::well_known::Rfc3339,
                )
                .is_err()
            {
                return Err(refused());
            }
            match (entry.epoch, entry.worker_id, entry.slot, entry.generation) {
                (None, None, None, None) => (),
                (Some(epoch), Some(worker), Some(slot), Some(generation))
                    if !epoch.is_nil()
                        && !worker.is_nil()
                        && (0..64).contains(&slot)
                        && generation > 0 => {}
                _ => return Err(refused()),
            }
            let fact = match (entry.kind.as_str(), entry.subject.as_deref()) {
                ("owner", None) => Entry::owner(entry.owner_id),
                ("reservation", Some(subject)) => {
                    Entry::reservation(entry.owner_id, subject.to_owned())?
                }
                _ => return Err(refused()),
            };
            let before = digest(&entry.previous_digest)?;
            let actual = digest(&entry.digest)?;
            if preceding.is_some_and(|expected| expected != before)
                || fact.extend_digest(before, entry.sequence)? != actual
            {
                return Err(refused());
            }
            preceding = Some(actual);
        }
        if after + expected == page.progress.sequence
            && preceding.is_some_and(|actual| hex(&actual) != page.progress.digest)
        {
            return Err(refused());
        }
        Ok(page)
    }

    /// The caller retains this durable owner through the subsequent primary
    /// write and cleanup. A successful append is not primary mutation authority.
    pub async fn history_reserve(
        &mut self,
        admission: &Admission,
        owner: Uuid,
        subject: &str,
    ) -> Result<Progress> {
        Entry::reservation(owner, subject.into())?;
        self.history_identity(admission, owner, subject, true).await
    }

    pub async fn history_check(
        &mut self,
        admission: &Admission,
        owner: Uuid,
        subject: &str,
    ) -> Result<Progress> {
        Entry::reservation(owner, subject.into())?;
        self.history_identity(admission, owner, subject, false)
            .await
    }

    async fn history_identity(
        &mut self,
        admission: &Admission,
        owner: Uuid,
        subject: &str,
        reserve: bool,
    ) -> Result<Progress> {
        if self.role != crate::organizations::witness::Role::Runtime {
            return Err(refused());
        }
        let query = if reserve {
            "SELECT organization_witness.history_reserve($1,$2,$3,$4,$5,$6,$7,$8)"
        } else {
            "SELECT organization_witness.history_check($1,$2,$3,$4,$5,$6,$7,$8)"
        };
        let result = progress(
            self.value(
                sqlx::query_scalar(query)
                    .bind(admission.scope.environment_id)
                    .bind(admission.scope.deployment_id)
                    .bind(admission.slot.slot)
                    .bind(admission.slot.generation)
                    .bind(admission.slot.epoch)
                    .bind(admission.slot.worker_id)
                    .bind(owner)
                    .bind(subject),
            )
            .await?,
            admission.scope,
        )?;
        if !result.sealed {
            return Err(refused());
        }
        Ok(result)
    }
}
