use super::*;
use crate::subject_ownership::history::sha256_hex;
use std::fs::{self as stdfs, DirBuilder, Permissions};
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("aegaeon-import-custody-{}", uuid::Uuid::new_v4()));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }
    fn source(&self, bytes: &[u8]) -> PathBuf {
        let path = self.0.join("input.jsonl");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_permissions(Permissions::from_mode(0o600)).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        stdfs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn organization_import_custody_parent_lease_and_capacity_bound_precede_creation() {
    let f = Fixture::new();
    for i in 0..63 {
        stdfs::create_dir(f.0.join(format!("prior-{i}"))).unwrap();
    }
    let last = Artifacts::create(&f.0.join("last-supported")).unwrap();
    assert!(Artifacts::create(&f.0.join("parallel")).is_err());
    assert!(!f.0.join("parallel").exists());
    drop(last);
    assert!(Artifacts::create(&f.0.join("over-capacity")).is_err());
    assert!(!f.0.join("over-capacity").exists());
    let f = Fixture::new();
    let first = Artifacts::create(&f.0.join("first")).unwrap();
    assert!(Artifacts::create(&f.0.join("second")).is_err());
    drop(first);
    assert!(Artifacts::create(&f.0.join("second")).is_ok());
}

#[test]
fn organization_import_custody_preserves_exact_private_bytes_and_never_overwrites() {
    let f = Fixture::new();
    let bytes = include_bytes!("../input/fixtures/independent-v1.jsonl");
    let source = f.source(bytes);
    let output = f.0.join("attempt");
    let artifacts = Artifacts::create(&output).unwrap();
    assert!(Artifacts::create(&output).is_err());
    let mut retained = artifacts.retain(&source, &sha256_hex(bytes)).unwrap();
    assert!(artifacts.retain(&source, &sha256_hex(bytes)).is_err());
    let mut read = Vec::new();
    retained.read_to_end(&mut read).unwrap();
    assert_eq!(read, bytes);
    let receipt = br#"{"activationAuthorized":false}"#;
    artifacts
        .complete(&mut retained, &sha256_hex(bytes), receipt)
        .unwrap();
    assert_eq!(stdfs::read(output.join("source.jsonl")).unwrap(), bytes);
    assert_eq!(stdfs::read(output.join("receipt.json")).unwrap(), receipt);
    assert!(!output.join("source.partial.jsonl").exists());
    for file in ["source.jsonl", "receipt.json"] {
        let meta = stdfs::metadata(output.join(file)).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o600);
        assert_eq!(meta.nlink(), 1);
    }
    assert_eq!(stdfs::metadata(&output).unwrap().mode() & 0o7777, 0o700);
    assert!(artifacts
        .complete(&mut retained, &sha256_hex(bytes), receipt)
        .is_err());
    assert!(artifacts.write("receipt.json", b"replacement").is_err());
    assert!(artifacts.write("../escape", b"replacement").is_err());
    assert!(!f.0.join("escape").exists());
}

#[test]
fn organization_import_custody_refuses_links_fifo_public_mode_and_bounds() {
    let f = Fixture::new();
    let source = f.source(b"input");
    let link = f.0.join("symlink");
    symlink(&source, &link).unwrap();
    assert!(open_private(&link, 10).is_err());
    let hard = f.0.join("hardlink");
    stdfs::hard_link(&source, &hard).unwrap();
    assert!(open_private(&source, 10).is_err());
    stdfs::remove_file(hard).unwrap();
    stdfs::set_permissions(&source, Permissions::from_mode(0o644)).unwrap();
    assert!(open_private(&source, 10).is_err());
    stdfs::set_permissions(&source, Permissions::from_mode(0o600)).unwrap();
    assert!(open_private(&source, 4).is_err());
    assert!(open_private(&source, 5).is_ok());
    let fifo = f.0.join("fifo");
    fs::mkfifoat(fs::CWD, &fifo, Mode::RUSR | Mode::WUSR).unwrap();
    assert!(
        open_private(&fifo, 10).is_err(),
        "NONBLOCK must reach the type refusal without a writer"
    );
    let public = f.0.join("public");
    stdfs::create_dir(&public).unwrap();
    stdfs::set_permissions(&public, Permissions::from_mode(0o755)).unwrap();
    assert!(Artifacts::create(&public.join("attempt")).is_err());
    let parent_link = f.0.join("parent-link");
    symlink(&f.0, &parent_link).unwrap();
    assert!(Artifacts::create(&parent_link.join("attempt")).is_err());
}

#[test]
fn organization_import_custody_failure_retains_partial_and_detects_changes_or_replacement() {
    let f = Fixture::new();
    let source = f.source(b"source");
    let bad = f.0.join("bad-digest");
    let artifacts = Artifacts::create(&bad).unwrap();
    assert!(artifacts.retain(&source, &"a".repeat(64)).is_err());
    assert_eq!(
        stdfs::read(bad.join("source.partial.jsonl")).unwrap(),
        b"source"
    );
    assert!(!bad.join("source.jsonl").exists());
    assert!(!bad.join("receipt.json").exists());
    drop(artifacts);
    let changed = f.0.join("changed");
    let artifacts = Artifacts::create(&changed).unwrap();
    let mut retained = artifacts.retain(&source, &sha256_hex(b"source")).unwrap();
    retained.write_all(b"CHANGED").unwrap();
    assert!(artifacts
        .complete(&mut retained, &sha256_hex(b"source"), b"{}")
        .is_err());
    assert!(changed.join("source.partial.jsonl").exists());
    drop(artifacts);
    let replaced = f.0.join("replaced");
    let artifacts = Artifacts::create(&replaced).unwrap();
    let mut retained = artifacts.retain(&source, &sha256_hex(b"source")).unwrap();
    stdfs::rename(
        replaced.join("source.partial.jsonl"),
        replaced.join("previous.jsonl"),
    )
    .unwrap();
    stdfs::write(replaced.join("source.partial.jsonl"), b"different").unwrap();
    assert!(artifacts
        .complete(&mut retained, &sha256_hex(b"source"), b"{}")
        .is_err());
    assert!(!replaced.join("source.jsonl").exists());
}

#[test]
fn organization_import_custody_conflicting_publication_never_replaces_existing_evidence() {
    let f = Fixture::new();
    let source = f.source(b"source");
    let output = f.0.join("attempt");
    let artifacts = Artifacts::create(&output).unwrap();
    let mut retained = artifacts.retain(&source, &sha256_hex(b"source")).unwrap();
    artifacts.write("source.jsonl", b"existing").unwrap();
    assert!(artifacts
        .complete(&mut retained, &sha256_hex(b"source"), b"{}")
        .is_err());
    assert_eq!(
        stdfs::read(output.join("source.jsonl")).unwrap(),
        b"existing"
    );
    assert!(output.join("source.partial.jsonl").exists());
    assert!(!output.join("receipt.json").exists());
    drop(artifacts);
    let output = f.0.join("receipt-conflict");
    let artifacts = Artifacts::create(&output).unwrap();
    let mut retained = artifacts.retain(&source, &sha256_hex(b"source")).unwrap();
    artifacts.write("receipt.json", b"existing").unwrap();
    assert!(artifacts
        .complete(&mut retained, &sha256_hex(b"source"), b"new")
        .is_err());
    assert_eq!(
        stdfs::read(output.join("receipt.json")).unwrap(),
        b"existing"
    );
    assert_eq!(
        stdfs::read(output.join("receipt.partial.json")).unwrap(),
        b"new"
    );
    assert_eq!(stdfs::read(output.join("source.jsonl")).unwrap(), b"source");
}
