//! Canonical independent history inputs. Syntax/inventory correspondence does
//! not certify external completeness, source custody or nonrollback storage.
use super::{Error, Result};
use crate::subject_ownership::history as source;
use aegaeon_crypto::hash::sha256_digest;
use serde::Serialize;
use uuid::Uuid;

pub mod cli;
mod control;
pub use control::{Page, Progress, StoredEntry};

#[cfg(test)]
mod tests;

const MAX_ENTRIES: usize = aegaeon_pure::organization_history::HISTORY_ENTRIES as usize;
pub const BATCH_ENTRIES: usize = aegaeon_pure::organization_history::HISTORY_BATCH as usize;

fn refused() -> Error {
    Error::Refused
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Owner,
    Reservation,
}

/// Exact ownership fact, without an authorization or activity assertion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Entry {
    kind: Kind,
    owner_id: Uuid,
    subject: Option<String>,
}
impl Entry {
    pub fn owner(owner_id: Uuid) -> Self {
        Self {
            kind: Kind::Owner,
            owner_id,
            subject: None,
        }
    }
    pub fn reservation(owner_id: Uuid, subject: String) -> Result<Self> {
        if subject.is_empty()
            || subject.len() > 255
            || !subject.is_ascii()
            || subject.contains('\0')
        {
            return Err(refused());
        }
        Ok(Self {
            kind: Kind::Reservation,
            owner_id,
            subject: Some(subject),
        })
    }
    fn extend_digest(&self, digest: [u8; 32], sequence: u64) -> Result<[u8; 32]> {
        let subject = self.subject.as_deref().unwrap_or("").as_bytes();
        let mut input = Vec::new();
        input.extend(digest);
        input.extend(sequence.to_be_bytes());
        input.extend([match self.kind {
            Kind::Owner => 0,
            Kind::Reservation => 1,
        }]);
        input.extend(self.owner_id.as_bytes());
        // Entry constructors enforce the existing 255-byte subject bound.
        input.extend(
            u32::try_from(subject.len())
                .map_err(|_| refused())?
                .to_be_bytes(),
        );
        input.extend(subject);
        Ok(sha256_digest(&input))
    }
}

fn initial_digest(environment_id: Uuid, issuer: &str) -> Result<[u8; 32]> {
    if issuer.is_empty() || issuer.len() > 1024 || issuer.contains('\0') {
        return Err(refused());
    }
    let length = u32::try_from(issuer.len()).map_err(|_| refused())?;
    let mut input = Vec::new();
    input.extend(b"aegaeon-permanent-history-v1\0");
    input.extend(environment_id.as_bytes());
    input.extend(length.to_be_bytes());
    input.extend(issuer.as_bytes());
    Ok(sha256_digest(&input))
}

fn hex(digest: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    digest
        .iter()
        .flat_map(|byte| {
            [
                char::from(ALPHABET[usize::from(byte >> 4)]),
                char::from(ALPHABET[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

/// A validated source/inventory union, ordered for finite witness import.
/// It is deliberately neither deserializable nor an activation capability.
pub struct Plan {
    environment_id: Uuid,
    issuer_host: String,
    receipt_id: Uuid,
    manifest_sha256: String,
    inventory_sha256: String,
    owner_count: usize,
    entries: Vec<Entry>,
    sources: Vec<source::model::Source>,
    digest: [u8; 32],
}
impl Plan {
    /// Source custody/completeness review must still precede enrollment. Expected
    /// raw hashes are supplied independently of the two documents being parsed.
    pub fn from_artifacts(
        manifest: &[u8],
        inventory: &[u8],
        expected_manifest_sha256: &str,
        expected_inventory_sha256: &str,
    ) -> Result<Self> {
        // Match the existing parser bounds before hashing caller-owned buffers.
        if manifest.len() > 64 * 1024 * 1024 || inventory.len() > 256 * 1024 * 1024 {
            return Err(refused());
        }
        let manifest_sha256 = source::sha256_hex(manifest);
        let inventory_sha256 = source::sha256_hex(inventory);
        if manifest_sha256 != expected_manifest_sha256
            || inventory_sha256 != expected_inventory_sha256
        {
            return Err(refused());
        }
        let manifest = source::parse_manifest(manifest).map_err(|_| refused())?;
        let inventory = source::parse_inventory(inventory).map_err(|_| refused())?;
        source::validate_union(&manifest, &inventory, &inventory_sha256).map_err(|_| refused())?;
        let environment_id =
            Uuid::parse_str(&manifest.namespace.environment_id).map_err(|_| refused())?;
        let receipt_id = Uuid::parse_str(&manifest.receipt_id).map_err(|_| refused())?;
        let mut digest = initial_digest(environment_id, &manifest.namespace.issuer_host)?;
        let mut owners = manifest
            .owners
            .iter()
            .map(|owner| Uuid::parse_str(&owner.owner_id).map_err(|_| refused()))
            .collect::<Result<Vec<_>>>()?;
        owners.sort_unstable();
        let owner_count = owners.len();
        let mut reservations = manifest.reservations;
        reservations.sort_unstable_by(|a, b| a.subject.as_bytes().cmp(b.subject.as_bytes()));
        let total = owner_count
            .checked_add(reservations.len())
            .filter(|count| *count <= MAX_ENTRIES)
            .ok_or_else(refused)?;
        let mut entries = Vec::with_capacity(total);
        entries.extend(owners.into_iter().map(Entry::owner));
        for reservation in reservations {
            entries.push(Entry::reservation(
                Uuid::parse_str(&reservation.owner_id).map_err(|_| refused())?,
                reservation.subject,
            )?);
        }
        for (index, entry) in entries.iter().enumerate() {
            let sequence = u64::try_from(index).map_err(|_| refused())? + 1;
            digest = entry.extend_digest(digest, sequence)?;
        }
        Ok(Self {
            environment_id,
            issuer_host: manifest.namespace.issuer_host,
            receipt_id,
            manifest_sha256,
            inventory_sha256,
            owner_count,
            entries,
            sources: manifest.sources,
            digest,
        })
    }
    pub fn environment_id(&self) -> Uuid {
        self.environment_id
    }
    pub fn issuer_host(&self) -> &str {
        &self.issuer_host
    }
    pub fn receipt_id(&self) -> Uuid {
        self.receipt_id
    }
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
    pub fn inventory_sha256(&self) -> &str {
        &self.inventory_sha256
    }
    pub fn counts(&self) -> (usize, usize) {
        (self.owner_count, self.entries.len() - self.owner_count)
    }
    pub fn digest(&self) -> String {
        hex(&self.digest)
    }
    pub fn batches(&self) -> impl Iterator<Item = &[Entry]> {
        self.entries.chunks(BATCH_ENTRIES)
    }
}
