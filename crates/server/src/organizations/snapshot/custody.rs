//! Descriptor-relative, private, non-overwriting import inspection artifacts.
use super::{hex_digest, MAX_TRANSFER_BYTES};
use aegaeon_crypto::hash::Sha256Hasher;
use rustix::fs::{self, Mode, OFlags, RenameFlags};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
#[error("Organizations import artifact refused: {0}")]
pub struct ArtifactError(&'static str);
type Result<T> = std::result::Result<T, ArtifactError>;

pub(crate) mod history;
pub(crate) mod identity;

#[cfg(test)]
mod tests;

pub struct Artifacts {
    directory: File,
    _parent_lease: File,
}

impl Artifacts {
    /// Creates a fresh private child inside an existing private owned directory.
    /// All later access is relative to the opened directory, not a mutable path.
    pub fn create(path: &Path) -> Result<Self> {
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .ok_or(ArtifactError("output directory name"))?;
        let parent = open_directory(parent_path)?;
        fs::flock(&parent, fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| ArtifactError("another inspection owns the output parent"))?;
        let entries = fs::Dir::read_from(&parent).map_err(|_| ArtifactError("output inventory"))?;
        let mut count = 0;
        for entry in entries {
            let entry = entry.map_err(|_| ArtifactError("output inventory"))?;
            if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                continue;
            }
            count += 1;
            if count >= 64 {
                return Err(ArtifactError("output directory capacity"));
            }
        }
        fs::mkdirat(&parent, name, Mode::RWXU)
            .map_err(|_| ArtifactError("new private output directory"))?;
        let directory = File::from(
            fs::openat(
                &parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ArtifactError("output directory open"))?,
        );
        private(&directory, true)?;
        parent
            .sync_all()
            .map_err(|_| ArtifactError("output parent synchronization"))?;
        Ok(Self {
            directory,
            _parent_lease: parent,
        })
    }

    /// Copy into an exclusive retained partial file before any database access.
    /// A mismatch retains that partial artifact and returns no usable input.
    pub fn retain(&self, source: &Path, expected_sha256: &str) -> Result<File> {
        if !valid_digest(expected_sha256) {
            return Err(ArtifactError("expected source digest"));
        }
        let mut input = open_private(source, MAX_TRANSFER_BYTES)?;
        let mut retained = self.new_file("source.partial.jsonl")?;
        let (digest, _) = copy(&mut input, Some(&mut retained), MAX_TRANSFER_BYTES)?;
        retained
            .sync_all()
            .map_err(|_| ArtifactError("source synchronization"))?;
        self.directory
            .sync_all()
            .map_err(|_| ArtifactError("source directory synchronization"))?;
        if digest != expected_sha256 {
            return Err(ArtifactError("retained source digest mismatch"));
        }
        retained
            .rewind()
            .map_err(|_| ArtifactError("retained source seek"))?;
        Ok(retained)
    }

    /// Recheck the exact retained bytes and atomically publish without replacement.
    /// Call only after native input, staging and supplier cleanup all succeed.
    pub fn complete(&self, source: &mut File, expected_sha256: &str, receipt: &[u8]) -> Result<()> {
        private(source, false)?;
        let entry = fs::statat(
            &self.directory,
            "source.partial.jsonl",
            fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| ArtifactError("retained source directory entry"))?;
        let opened = source
            .metadata()
            .map_err(|_| ArtifactError("retained source identity"))?;
        if entry.st_dev != opened.dev() || entry.st_ino != opened.ino() {
            return Err(ArtifactError("retained source directory entry changed"));
        }
        source
            .rewind()
            .map_err(|_| ArtifactError("retained source seek"))?;
        if copy(source, None, MAX_TRANSFER_BYTES)?.0 != expected_sha256 {
            return Err(ArtifactError("retained source changed during inspection"));
        }
        self.publish("source.partial.jsonl", "source.jsonl")?;
        self.write("receipt.partial.json", receipt)?;
        self.publish("receipt.partial.json", "receipt.json")
    }

    /// Fixed internal artifact names only; never derive names from input JSON.
    pub fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        if !matches!(
            name,
            "tool-source-record.json"
                | "dirty-source-input.json"
                | "failure.json"
                | "receipt.partial.json"
                | "receipt.json"
                | "source.jsonl"
        ) {
            return Err(ArtifactError("unknown internal metadata artifact"));
        }
        if bytes.len() > 1024 * 1024 {
            return Err(ArtifactError("metadata byte limit"));
        }
        let mut file = self.new_file(name)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ArtifactError("metadata synchronization"))?;
        self.directory
            .sync_all()
            .map_err(|_| ArtifactError("metadata directory synchronization"))
    }

    fn new_file(&self, name: &str) -> Result<File> {
        if name.contains('/') || matches!(name, "" | "." | "..") {
            return Err(ArtifactError("artifact name"));
        }
        let file = File::from(
            fs::openat(
                &self.directory,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| ArtifactError("new private artifact"))?,
        );
        private(&file, false)?;
        Ok(file)
    }

    fn publish(&self, from: &str, to: &str) -> Result<()> {
        fs::renameat_with(
            &self.directory,
            from,
            &self.directory,
            to,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| ArtifactError("non-overwriting publication"))?;
        self.directory
            .sync_all()
            .map_err(|_| ArtifactError("publication directory synchronization"))
    }
}

pub fn open_private(path: &Path, maximum: u64) -> Result<File> {
    // NONBLOCK prevents a substituted FIFO from blocking before fstat refusal.
    let file = File::from(
        fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ArtifactError("private input open"))?,
    );
    private(&file, false)?;
    if file
        .metadata()
        .map_err(|_| ArtifactError("input metadata"))?
        .len()
        > maximum
    {
        return Err(ArtifactError("input byte limit"));
    }
    Ok(file)
}

fn open_directory(path: &Path) -> Result<File> {
    let file = File::from(
        fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ArtifactError("private parent open"))?,
    );
    private(&file, true)?;
    Ok(file)
}

pub(super) fn private_socket_directory(path: &Path) -> Result<()> {
    open_directory(path).map(|_| ())
}

fn private(file: &File, directory: bool) -> Result<()> {
    let stat = file
        .metadata()
        .map_err(|_| ArtifactError("file identity"))?;
    if stat.uid() != rustix::process::geteuid().as_raw()
        || stat.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !stat.is_dir()
        } else {
            !stat.is_file() || stat.nlink() != 1
        }
    {
        return Err(ArtifactError("private owner, mode, type or link count"));
    }
    Ok(())
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn copy(input: &mut File, mut output: Option<&mut File>, maximum: u64) -> Result<(String, u64)> {
    let mut hash = Sha256Hasher::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|_| ArtifactError("input read"))?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .filter(|n| *n <= maximum)
            .ok_or(ArtifactError("input byte limit"))?;
        hash.update(&buffer[..count]);
        if let Some(file) = output.as_mut() {
            file.write_all(&buffer[..count])
                .map_err(|_| ArtifactError("retained source write"))?;
        }
    }
    Ok((hex_digest(&hash.finalize()), bytes))
}
