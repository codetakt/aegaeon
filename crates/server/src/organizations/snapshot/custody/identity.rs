//! Shared executable/source binding for private maintenance artifacts.
use super::Artifacts;
use crate::subject_ownership::history::{
    artifacts::file_identity, model::ToolSourceIdentity, parse_strict, sha256_hex,
};
use std::{io::Read, path::Path};
type Result<T> = std::result::Result<T, String>;

fn read_private(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    super::open_private(path, maximum)
        .map_err(|e| e.to_string())?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "private metadata read".to_string())?;
    if bytes.len() as u64 > maximum {
        return Err("private metadata byte limit".into());
    }
    Ok(bytes)
}

pub(crate) fn tool_source(
    record: &Path,
    dirty_record: Option<&Path>,
    output: &Artifacts,
) -> Result<ToolSourceIdentity> {
    let raw = read_private(record, 16384)?;
    let value = parse_strict(&raw, 16384).map_err(|_| "tool source record syntax".to_string())?;
    let source: ToolSourceIdentity =
        serde_json::from_value(value).map_err(|_| "tool source record shape".to_string())?;
    let git = |s: &str| {
        s.len() == 40
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if !super::valid_digest(&source.tool_sha256)
        || !git(&source.source_tree)
        || source.source_commit.as_ref().is_some_and(|s| !git(s))
        || source
            .dirty_input_sha256
            .as_ref()
            .is_some_and(|s| !super::valid_digest(s))
        || source.source_commit.is_none() && source.dirty_input_sha256.is_none()
    {
        return Err("tool source labels invalid".into());
    }
    let executable = std::env::current_exe().map_err(|_| "executable identity".to_string())?;
    if std::fs::metadata(&executable)
        .map_err(|_| "executable metadata".to_string())?
        .len()
        > 1024 * 1024 * 1024
        || file_identity(&executable)
            .map_err(|_| "executable hash".to_string())?
            .0
            != source.tool_sha256
    {
        return Err("executable differs from reviewed source record".into());
    }
    match (&source.dirty_input_sha256, dirty_record) {
        (Some(expected), Some(path)) => {
            let bytes = read_private(path, 1024 * 1024)?;
            if sha256_hex(&bytes) != *expected {
                return Err("dirty source record digest mismatch".into());
            }
            output
                .write("dirty-source-input.json", &bytes)
                .map_err(|e| e.to_string())?;
        }
        (None, None) => (),
        _ => return Err("dirty source record must exactly match build labels".into()),
    }
    output
        .write("tool-source-record.json", &raw)
        .map_err(|e| e.to_string())?;
    Ok(source)
}
