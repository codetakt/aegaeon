//! Incremental input validation for inactive import staging. Returned rows are
//! untrusted until EOF/manifest/digest validation, and never convey authority.
use super::{
    hex_digest, section_digest, MAX_KEY_BYTES, MAX_ROW_BYTES, MAX_SECTION_ROWS, MAX_TRANSFER_BYTES,
    SECTIONS,
};
use crate::organizations::Scope;
use crate::subject_ownership::history::HashChain;
use aegaeon_crypto::hash::Sha256Hasher;
use serde::Serialize;
use serde_json::Value;
use std::io::{BufRead, Read};
use uuid::Uuid;

mod envelope;
mod syntax;
#[cfg(test)]
mod tests;

pub const MAX_LINE_BYTES: usize = 320 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("invalid Organizations snapshot at record {record}: {reason}")]
pub struct InputError {
    pub record: u64,
    pub reason: &'static str,
}

type Result<T> = std::result::Result<T, InputError>;

/// A bounded row for private temporary staging, not an accepted import record.
#[derive(Debug)]
pub struct PendingRow {
    pub section: &'static str,
    pub key: String,
    pub data: Value,
    pub exact_data: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityReceipt {
    pub snapshot_id: Uuid,
    pub scope: Scope,
    pub bytes: u64,
    pub sha256: String,
    pub sections: Vec<envelope::Digest>,
    // Fixed false; never caller-controlled or deserialized.
    import_authorized: bool,
}

pub struct Input<R> {
    source: R,
    header: envelope::Header,
    expected_sha256: String,
    chains: Vec<HashChain>,
    previous: Vec<Option<String>>,
    position: usize,
    bytes: u64,
    record: u64,
    whole: Sha256Hasher,
    failed: bool,
    receipt: Option<IntegrityReceipt>,
}

impl<R: BufRead> Input<R> {
    /// The caller owns a bounded/deadlined input and private inactive staging.
    /// The expected scope/digest must come from its separately adopted source.
    pub fn new(mut source: R, scope: Scope, expected_sha256: &str) -> Result<Self> {
        let error = |reason| InputError { record: 1, reason };
        if scope.validate().is_err() || !envelope::is_digest(expected_sha256) {
            return Err(error("invalid expected scope or digest"));
        }
        let line = read_line(&mut source).map_err(error)?;
        let value = syntax::parse(&line).map_err(error)?;
        let header = envelope::header(&value, scope).map_err(error)?;
        let mut whole = Sha256Hasher::new();
        whole.update(&line);
        Ok(Self {
            source,
            header,
            expected_sha256: expected_sha256.into(),
            chains: SECTIONS.iter().map(|s| section_digest(s.name)).collect(),
            previous: vec![None; SECTIONS.len()],
            position: 0,
            bytes: line.len() as u64,
            record: 1,
            whole,
            failed: false,
            receipt: None,
        })
    }

    /// Returns only preparation rows. An error permanently poisons this input.
    /// `None` means the terminal manifest, EOF and explicit whole digest matched.
    pub fn next_row(&mut self) -> Result<Option<PendingRow>> {
        if self.failed {
            return Err(self.error("input already failed"));
        }
        if self.receipt.is_some() {
            return Ok(None);
        }
        let result = self.next_checked();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Consumes an entirely validated stream. This receipt is not activation.
    pub fn finish(self) -> Result<IntegrityReceipt> {
        if self.failed {
            return Err(self.error("input already failed"));
        }
        let error = self.error("input was not completely consumed");
        self.receipt.ok_or(error)
    }

    fn error(&self, reason: &'static str) -> InputError {
        InputError {
            record: self.record,
            reason,
        }
    }

    fn next_checked(&mut self) -> Result<Option<PendingRow>> {
        self.record = self
            .record
            .checked_add(1)
            .ok_or_else(|| self.error("record count overflow"))?;
        let raw = read_line(&mut self.source).map_err(|reason| self.error(reason))?;
        let previous_bytes = self.bytes;
        self.bytes = self
            .bytes
            .checked_add(raw.len() as u64)
            .filter(|n| *n <= MAX_TRANSFER_BYTES)
            .ok_or_else(|| self.error("transfer byte limit"))?;
        self.whole.update(&raw);
        let value = syntax::parse(&raw).map_err(|reason| self.error(reason))?;
        if value.get("record").and_then(Value::as_str) == Some("manifest") {
            self.complete(&value, previous_bytes)?;
            return Ok(None);
        }
        self.row(&raw, value).map(Some)
    }

    fn row(&mut self, raw: &[u8], mut value: Value) -> Result<PendingRow> {
        let row: envelope::Row<'_> =
            serde_json::from_slice(raw).map_err(|_| self.error("row envelope"))?;
        let Some(position) = SECTIONS.iter().position(|s| s.name == row.section) else {
            return Err(self.error("unknown section"));
        };
        if row.record != "row"
            || position < self.position
            || row.key.len() > MAX_KEY_BYTES
            || row.data.get().len() > MAX_ROW_BYTES
            || self.previous[position]
                .as_ref()
                .is_some_and(|p| p >= &row.key)
            || self.chains[position].finish().0 >= MAX_SECTION_ROWS
        {
            return Err(self.error("row ordering or bound"));
        }
        let data = value
            .get_mut("data")
            .map(Value::take)
            .filter(Value::is_object)
            .ok_or_else(|| self.error("row data object"))?;
        for (name, expected) in [
            ("environment_id", self.header.scope.environment_id),
            ("domain_id", self.header.scope.domain_id),
        ] {
            if data
                .get(name)
                .is_some_and(|v| v.as_str() != Some(expected.to_string().as_str()))
            {
                return Err(self.error("row scope"));
            }
        }
        self.chains[position]
            .push(&row.key, row.data.get().as_bytes())
            .map_err(|_| self.error("section count overflow"))?;
        self.previous[position] = Some(row.key.clone());
        self.position = position;
        Ok(PendingRow {
            section: SECTIONS[position].name,
            key: row.key,
            data,
            exact_data: row.data.get().into(),
        })
    }

    fn complete(&mut self, value: &Value, previous_bytes: u64) -> Result<()> {
        let sections: Vec<_> = SECTIONS
            .iter()
            .zip(&self.chains)
            .map(|(section, chain)| {
                let (count, digest) = chain.finish();
                envelope::Digest {
                    section: section.name.into(),
                    count,
                    sha256: hex_digest(&digest),
                }
            })
            .collect();
        envelope::manifest(value, &self.header, previous_bytes, &sections)
            .map_err(|reason| self.error(reason))?;
        let mut trailing = [0u8; 1];
        match self.source.read(&mut trailing) {
            Ok(0) => (),
            Ok(_) => return Err(self.error("trailing bytes")),
            Err(_) => return Err(self.error("input read failed")),
        }
        let digest = hex_digest(&std::mem::take(&mut self.whole).finalize());
        if digest != self.expected_sha256 {
            return Err(self.error("expected whole-file digest mismatch"));
        }
        self.receipt = Some(IntegrityReceipt {
            snapshot_id: self.header.snapshot_id,
            scope: self.header.scope,
            bytes: self.bytes,
            sha256: digest,
            sections,
            import_authorized: false,
        });
        Ok(())
    }
}

fn read_line(source: &mut impl BufRead) -> std::result::Result<Vec<u8>, &'static str> {
    let mut line = Vec::new();
    source
        .take(MAX_LINE_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(|_| "input read failed")?;
    if line.len() > MAX_LINE_BYTES || !line.ends_with(b"\n") {
        return Err("truncated input or line limit");
    }
    Ok(line)
}
