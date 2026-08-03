#![allow(dead_code)]

use std::fmt::Display;
use std::fs;
use std::path::{Path, PathBuf};

pub type TestResult = Result<(), String>;

pub trait TestContext<T> {
    fn test_context(self, context: &str) -> Result<T, String>;
}

impl<T, E: Display> TestContext<T> for Result<T, E> {
    fn test_context(self, context: &str) -> Result<T, String> {
        self.map_err(|err| format!("{context}: {err}"))
    }
}

impl<T> TestContext<T> for Option<T> {
    fn test_context(self, context: &str) -> Result<T, String> {
        self.ok_or_else(|| context.to_string())
    }
}

pub fn server_source(relative_path: &str, description: &str) -> Result<String, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join(relative_path);
    fs::read_to_string(&path).test_context(&format!(
        "{description} should be readable at {}",
        path.display()
    ))
}

pub fn repository_file(relative_path: &str, description: &str) -> Result<String, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join("../..").join(relative_path);
    fs::read_to_string(&path).test_context(&format!(
        "{description} should be readable at {}",
        path.display()
    ))
}

pub fn repo_source(relative_path: &str, description: &str) -> Result<String, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .test_context("server crate should live under crates/server")?;
    let path = repo_root.join(relative_path);
    fs::read_to_string(&path).test_context(&format!(
        "{description} should be readable at {}",
        path.display()
    ))
}

/// Concatenated contents of every versioned migration in `db/migrations`.
///
/// Guard tests assert invariant markers against the migration inventory as a
/// whole rather than naming individual files, so the assertions survive
/// migration squashes/baselines.
pub fn migrations_source() -> Result<String, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .test_context("server crate should live under crates/server")?;
    let dir = repo_root.join("db/migrations");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .test_context(&format!(
            "db/migrations should be readable at {}",
            dir.display()
        ))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sql"))
        .collect();
    paths.sort();
    if paths.is_empty() {
        return Err(format!(
            "db/migrations contains no .sql files at {}",
            dir.display()
        ));
    }
    let mut combined = String::new();
    for path in paths {
        combined.push_str(&fs::read_to_string(&path).test_context(&format!(
            "migration should be readable at {}",
            path.display()
        ))?);
        combined.push('\n');
    }
    Ok(combined)
}

pub fn rust_sources(roots: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for root in roots {
        collect_rust_sources(root, &mut files)?;
    }
    Ok(files)
}

fn collect_rust_sources(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    if path.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }

    for entry in fs::read_dir(path).test_context(&format!(
        "source directory should be readable: {}",
        path.display()
    ))? {
        let entry = entry.test_context("source directory entry should be readable")?;
        collect_rust_sources(&entry.path(), files)?;
    }
    Ok(())
}

pub fn section_between<'a>(source: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let start_offset = source.find(start)? + start.len();
    let end_offset = source[start_offset..].find(end)? + start_offset;
    source.get(start_offset..end_offset)
}

pub fn function_body<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let signature_offset = source.find(signature)?;
    let open_brace = source[signature_offset..]
        .find('{')
        .map(|index| signature_offset + index)?;
    let close_brace = matching_brace(source, open_brace)?;
    source.get(open_brace + 1..close_brace)
}

pub fn assert_ordered_markers(source: &str, markers: &[&str], context: &str) -> TestResult {
    let mut cursor = 0usize;
    for marker in markers {
        let Some(relative_offset) = source[cursor..].find(marker) else {
            return Err(format!("{context}: missing ordered marker `{marker}`"));
        };
        cursor += relative_offset + marker.len();
    }
    Ok(())
}

fn matching_brace(source: &str, open_brace: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in source[open_brace..].char_indices() {
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open_brace + index);
                }
            }
            _ => {}
        }
    }
    None
}
