//! Explicit local source mappings and private, create-new retention artifacts.
use super::model::Manifest;
use super::{sha256_hex, HistoryInputError};
use ring::digest::{Context, SHA256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, HistoryInputError>;
fn failure(reason: &'static str) -> HistoryInputError {
    HistoryInputError(reason.into())
}

/// Each invocation owns a new directory. Failed files remain available for review.
pub struct PrivateArtifacts {
    directory: PathBuf,
}
impl PrivateArtifacts {
    /// # Errors
    /// Refuses an existing output location or any filesystem failure.
    pub fn create(directory: &Path) -> Result<Self> {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .map_err(|_| failure("cannot create new private output directory"))?;
        Ok(Self {
            directory: directory.to_owned(),
        })
    }
    pub(super) fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut output = self.new_file(name)?;
        output
            .write_all(bytes)
            .and_then(|()| output.sync_all())
            .map_err(|_| failure("cannot retain private artifact"))
    }
    pub(super) fn new_file(&self, name: &str) -> Result<File> {
        if name.contains('/') || name == "." || name == ".." {
            return Err(failure("invalid internal artifact name"));
        }
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(self.directory.join(name))
            .map_err(|_| failure("cannot create private artifact"))
    }
    /// Hash and copy all explicitly mapped source bytes before database access.
    /// Manifest references are labels; this method never resolves them as paths.
    /// # Errors
    /// Refuses missing, repeated, unused or changed mappings and hash/length mismatch.
    pub fn retain_sources(
        &self,
        manifest: &Manifest,
        mappings: &[(String, PathBuf)],
    ) -> Result<()> {
        let mut paths = HashMap::new();
        for (id, path) in mappings {
            if paths.insert(id.as_str(), path).is_some() {
                return Err(failure("duplicate explicit source mapping"));
            }
        }
        if paths.len() != manifest.sources.len() {
            return Err(failure("missing or unused explicit source mapping"));
        }
        for source in &manifest.sources {
            let path = paths
                .remove(source.source_id.as_str())
                .ok_or_else(|| failure("missing explicit source mapping"))?;
            let mut input = open_regular(path)?;
            let mut output = self.new_file(&format!("source-{}.bin", source.source_id))?;
            let (hash, length) = copy_digest(&mut input, Some(&mut output))?;
            output
                .sync_all()
                .map_err(|_| failure("cannot sync retained source"))?;
            if hash != source.sha256 || length != source.byte_length {
                return Err(failure("source hash or byte length mismatch"));
            }
        }
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| failure("cannot sync artifact directory"))?;
        Ok(())
    }
    /// Recheck the exact retained sources immediately before an explicit commit.
    /// # Errors
    /// Refuses source replacement, truncation or any changed hash/byte length.
    pub fn recheck_sources(&self, manifest: &Manifest) -> Result<()> {
        for source in &manifest.sources {
            let mut file = open_regular(
                &self
                    .directory
                    .join(format!("source-{}.bin", source.source_id)),
            )?;
            let (hash, length) = copy_digest(&mut file, None)?;
            if hash != source.sha256 || length != source.byte_length {
                return Err(failure("retained source changed before commit"));
            }
        }
        Ok(())
    }
}

fn open_regular(path: &Path) -> Result<File> {
    let before =
        fs::symlink_metadata(path).map_err(|_| failure("source is not a readable regular file"))?;
    if !before.is_file() {
        return Err(failure("source is not a regular file"));
    }
    let file = File::open(path).map_err(|_| failure("source cannot be opened"))?;
    let opened = file
        .metadata()
        .map_err(|_| failure("source identity cannot be read"))?;
    if !opened.is_file() || before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(failure("source changed during open"));
    }
    Ok(file)
}
fn copy_digest(input: &mut File, mut output: Option<&mut File>) -> Result<(String, u64)> {
    let mut hash = Context::new(&SHA256);
    let mut length = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|_| failure("source read failed"))?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| failure("source byte length unsupported"))?;
        hash.update(&buffer[..count]);
        if let Some(file) = output.as_mut() {
            file.write_all(&buffer[..count])
                .map_err(|_| failure("source retention failed"))?;
        }
    }
    Ok((super::digest::hex_digest(hash.finish().as_ref()), length))
}

/// Read a bounded raw document before any parser allocation or database access.
/// # Errors
/// Refuses nonregular files, failed reads or documents above the explicit bound.
pub fn read_document(path: &Path, max_bytes: usize) -> Result<(Vec<u8>, String)> {
    let file = open_regular(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure("history document read failed"))?;
    if bytes.len() > max_bytes {
        return Err(failure("history document exceeds byte limit"));
    }
    let hash = sha256_hex(&bytes);
    Ok((bytes, hash))
}

/// Compute the identity of an explicitly selected regular file without loading it.
/// # Errors
/// Refuses nonregular/unreadable files or unsupported byte lengths.
pub fn file_identity(path: &Path) -> Result<(String, u64)> {
    copy_digest(&mut open_regular(path)?, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn retained_sources_are_private_create_new_and_rechecked() {
        let root = std::env::temp_dir().join(format!(
            "aegaeon-history-artifacts-{}",
            uuid::Uuid::new_v4()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let source_path = root.join("source");
        fs::write(&source_path, b"attestation").unwrap();
        let mut value = super::super::validation::tests::manifest();
        value["sources"][0]["sha256"] = serde_json::json!(sha256_hex(b"attestation"));
        value["sources"][0]["byte_length"] = serde_json::json!(11);
        let manifest = super::super::parse_manifest(&serde_json::to_vec(&value).unwrap()).unwrap();
        let directory = root.join("attempt");
        let output = PrivateArtifacts::create(&directory).unwrap();
        let mappings = vec![("attestation".into(), source_path.clone())];
        assert!(output.retain_sources(&manifest, &[]).is_err());
        assert!(output
            .retain_sources(&manifest, &[mappings[0].clone(), mappings[0].clone()])
            .is_err());
        output.retain_sources(&manifest, &mappings).unwrap();
        output.recheck_sources(&manifest).unwrap();
        assert!(PrivateArtifacts::create(&directory).is_err());
        assert!(output.retain_sources(&manifest, &mappings).is_err());
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let retained = directory.join("source-attestation.bin");
        assert_eq!(
            fs::metadata(&retained).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::write(&retained, b"changed").unwrap();
        assert!(output.recheck_sources(&manifest).is_err());
        assert!(read_document(&source_path, 10).is_err());
        let linked = root.join("linked");
        symlink(&source_path, &linked).unwrap();
        assert!(read_document(&linked, 100).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
