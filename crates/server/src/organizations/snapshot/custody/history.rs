//! Fixed-name, bounded retention for independent ownership history commands.
use super::*;
use std::io::Read;

pub(crate) const JOURNAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum InputKind {
    Manifest,
    Inventory,
    Source(u8),
}

pub(crate) struct Retained {
    file: File,
    name: String,
    digest: String,
    length: u64,
}
impl Retained {
    pub(crate) fn bytes(&mut self, maximum: u64) -> Result<Vec<u8>> {
        if self.length > maximum {
            return Err(ArtifactError("metadata byte limit"));
        }
        self.file
            .rewind()
            .map_err(|_| ArtifactError("input seek"))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut self.file)
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ArtifactError("input read"))?;
        if bytes.len() as u64 != self.length
            || super::super::hex_digest(&aegaeon_crypto::hash::sha256_digest(&bytes)) != self.digest
        {
            return Err(ArtifactError("retained input changed"));
        }
        Ok(bytes)
    }
    pub(crate) fn recheck(&mut self, output: &Artifacts) -> Result<()> {
        output.check_entry(&self.file, &self.name)?;
        self.file
            .rewind()
            .map_err(|_| ArtifactError("input seek"))?;
        if copy(&mut self.file, None, self.length)? != (self.digest.clone(), self.length) {
            return Err(ArtifactError("retained input changed"));
        }
        Ok(())
    }
}

impl Artifacts {
    pub(crate) fn retain_history(
        &self,
        kind: InputKind,
        source: &Path,
        expected: &str,
        declared_length: Option<u64>,
    ) -> Result<Retained> {
        let (name, maximum) = match kind {
            InputKind::Manifest => ("manifest.json".to_owned(), 64 * 1024 * 1024),
            InputKind::Inventory => ("inventory.json".to_owned(), 256 * 1024 * 1024),
            InputKind::Source(index) => (format!("source-{index:03}.bin"), MAX_TRANSFER_BYTES),
        };
        if !valid_digest(expected) || declared_length.is_some_and(|n| n > maximum) {
            return Err(ArtifactError("history input bounds"));
        }
        let maximum = declared_length.unwrap_or(maximum);
        let mut input = open_private(source, maximum)?;
        let mut file = self.new_file(&name)?;
        let (digest, length) = copy(&mut input, Some(&mut file), maximum)?;
        file.sync_all()
            .map_err(|_| ArtifactError("input synchronization"))?;
        self.directory
            .sync_all()
            .map_err(|_| ArtifactError("input directory synchronization"))?;
        if digest != expected || declared_length.is_some_and(|n| n != length) {
            return Err(ArtifactError("history input identity mismatch"));
        }
        Ok(Retained {
            file,
            name,
            digest,
            length,
        })
    }

    fn check_entry(&self, file: &File, name: &str) -> Result<()> {
        private(file, false)?;
        let entry = fs::statat(&self.directory, name, fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ArtifactError("retained directory entry"))?;
        let opened = file
            .metadata()
            .map_err(|_| ArtifactError("retained file identity"))?;
        if entry.st_dev != opened.dev() || entry.st_ino != opened.ino() {
            return Err(ArtifactError("retained directory entry changed"));
        }
        Ok(())
    }

    pub(crate) fn history_journal(&self) -> Result<File> {
        self.new_file("history.partial.jsonl")
    }

    pub(crate) fn complete_history(
        &self,
        journal: &mut File,
        expected: &str,
        receipt: &[u8],
    ) -> Result<()> {
        self.check_entry(journal, "history.partial.jsonl")?;
        journal
            .sync_all()
            .map_err(|_| ArtifactError("journal synchronization"))?;
        journal
            .rewind()
            .map_err(|_| ArtifactError("journal seek"))?;
        if copy(journal, None, JOURNAL_BYTES)?.0 != expected {
            return Err(ArtifactError("retained journal changed"));
        }
        self.publish("history.partial.jsonl", "history.jsonl")?;
        self.write("receipt.partial.json", receipt)?;
        self.publish("receipt.partial.json", "receipt.json")
    }
}
