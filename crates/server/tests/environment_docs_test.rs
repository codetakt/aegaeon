use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt::Display;
use std::fs;
use std::path::Path;

const INTENTIONALLY_UNDOCUMENTED_TEST_HELPERS: &[&str] = &[
    "AEGAEON_",
    "AEGAEON_CONFIG_TEST_ACCESS_TOKEN_TTL",
    "AEGAEON_CONFIG_TEST_LEGACY_NUM",
    "AEGAEON_CONFIG_TEST_NUM",
    "AEGAEON_CONFIG_TEST_REFRESH_TOKEN_TTL",
    "AEGAEON_MAIN_TEST_FLAG",
    "AEGAEON_MAIN_TEST_NON_UNICODE_FLAG",
    "AEGAEON_MAIN_TEST_NON_UNICODE_NUM",
    "AEGAEON_MAIN_TEST_NON_UNICODE_SECRET",
    "AEGAEON_MAIN_TEST_NUM",
    "AEGAEON_MAIN_TEST_OPTIONAL_TRIMMED",
    "AEGAEON_MAIN_TEST_SECRET",
    "AEGAEON_TEST_",
];

type TestResult = Result<(), String>;

trait TestContext<T> {
    fn test_context(self, context: &str) -> Result<T, String>;
}

impl<T, E: Display> TestContext<T> for Result<T, E> {
    fn test_context(self, context: &str) -> Result<T, String> {
        self.map_err(|err| format!("{context}: {err}"))
    }
}

#[test]
fn environment_documentation_covers_server_env_var_literals() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");

    let mut code_vars = BTreeSet::new();
    collect_rust_env_literals(&src_dir, &mut code_vars)?;
    for helper in INTENTIONALLY_UNDOCUMENTED_TEST_HELPERS {
        code_vars.remove(*helper);
    }

    let doc = environment_docs_text(manifest_dir)?;
    let documented_vars = extract_env_vars(&doc);
    let missing = code_vars
        .difference(&documented_vars)
        .cloned()
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "docs/configurations/environment/ must document server env vars: {}",
        missing.join(", ")
    );
    Ok(())
}

#[test]
fn non_aegaeon_environment_literals_are_classified_by_runtime_boundary() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");

    let mut code_vars = BTreeSet::new();
    collect_rust_non_aegaeon_env_literals(&src_dir, &mut code_vars)?;

    let expected = BTreeSet::from([
        "AWS_ACCESS_KEY_ID".to_string(),
        "AWS_ENDPOINT_URL".to_string(),
        "AWS_KMS_KEY_ID".to_string(),
        "AWS_REGION".to_string(),
        "AWS_SECRET_ACCESS_KEY".to_string(),
        "BASE_URL".to_string(),
        "DATABASE_URL".to_string(),
        "KMS_CONFIG_FILE".to_string(),
        "REDIS_URL".to_string(),
    ]);
    assert_eq!(
        code_vars, expected,
        "non-AEGAEON env literals must be classified explicitly before use"
    );

    let doc = environment_docs_text(manifest_dir)?;
    assert!(
        doc.contains("`BASE_URL` | _removed_"),
        "legacy BASE_URL must remain documented as removed"
    );
    assert!(
        doc.contains("`AEGAEON_HOSTED_BOOTSTRAP_KMS_REGION` | `AWS_REGION` fallback"),
        "AWS_REGION must remain documented only as a hosted-bootstrap fallback"
    );
    for test_only_legacy_kms_env in ["AWS_KMS_KEY_ID", "KMS_CONFIG_FILE"] {
        assert!(
            !doc.contains(&format!("`{test_only_legacy_kms_env}`")),
            "{test_only_legacy_kms_env} is test-only legacy KMS evidence input and must not appear as a supported server runtime env"
        );
    }

    let kms_mod = fs::read_to_string(manifest_dir.join("src/kms/mod.rs"))
        .test_context("kms module source should be readable")?;
    assert!(
        kms_mod.contains("#[cfg(all(feature = \"kms-aws\", test))]\nmod legacy_aws_evidence;"),
        "legacy generic AWS KMS helper must remain test-only"
    );
    Ok(())
}

fn environment_docs_text(manifest_dir: &Path) -> Result<String, String> {
    let split_dir = manifest_dir.join("../../docs/configurations/environment");
    let mut paths = fs::read_dir(&split_dir)
        .test_context("environment split docs directory should be readable")?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == OsStr::new("md")))
        .collect::<Vec<_>>();
    paths.sort();

    let mut combined = String::new();
    for path in paths {
        combined.push_str(
            &fs::read_to_string(&path)
                .test_context(&format!("{} should be readable", path.display()))?,
        );
        combined.push('\n');
    }
    Ok(combined)
}

fn collect_rust_env_literals(dir: &Path, out: &mut BTreeSet<String>) -> TestResult {
    for entry in fs::read_dir(dir).test_context("source directory should be readable")? {
        let entry = entry.test_context("source directory entry should be readable")?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_env_literals(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == OsStr::new("rs")) {
            let source = fs::read_to_string(&path).test_context(&format!(
                "Rust source should be readable: {}",
                path.display()
            ))?;
            out.extend(extract_quoted_env_vars(&source));
        }
    }
    Ok(())
}

fn collect_rust_non_aegaeon_env_literals(dir: &Path, out: &mut BTreeSet<String>) -> TestResult {
    for entry in fs::read_dir(dir).test_context("source directory should be readable")? {
        let entry = entry.test_context("source directory entry should be readable")?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_non_aegaeon_env_literals(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == OsStr::new("rs")) {
            let source = fs::read_to_string(&path).test_context(&format!(
                "Rust source should be readable: {}",
                path.display()
            ))?;
            out.extend(extract_quoted_non_aegaeon_env_vars(&source));
        }
    }
    Ok(())
}

fn extract_quoted_env_vars(source: &str) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();
    let mut offset = 0;
    while let Some(found) = source[offset..].find("\"AEGAEON_") {
        let start = offset + found + 1;
        let end = env_var_end(source, start);
        vars.insert(source[start..end].to_string());
        offset = end;
    }
    vars
}

fn extract_quoted_non_aegaeon_env_vars(source: &str) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();
    let mut offset = 0;
    while let Some(found) = source[offset..].find('"') {
        let start = offset + found + 1;
        let Some(end_rel) = source[start..].find('"') else {
            break;
        };
        let end = start + end_rel;
        let value = &source[start..end];
        if is_non_aegaeon_env_literal(value) {
            vars.insert(value.to_string());
        }
        offset = end + 1;
    }
    vars
}

fn is_non_aegaeon_env_literal(value: &str) -> bool {
    matches!(
        value,
        "BASE_URL" | "DATABASE_URL" | "KMS_CONFIG_FILE" | "REDIS_URL"
    ) || value.starts_with("AWS_")
}

fn extract_env_vars(text: &str) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();
    let mut offset = 0;
    while let Some(found) = text[offset..].find("AEGAEON_") {
        let start = offset + found;
        let end = env_var_end(text, start);
        vars.insert(text[start..end].to_string());
        offset = end;
    }
    vars
}

fn env_var_end(text: &str, start: usize) -> usize {
    text[start..]
        .char_indices()
        .find_map(|(idx, ch)| (!is_env_var_char(ch)).then_some(start + idx))
        .unwrap_or(text.len())
}

const fn is_env_var_char(ch: char) -> bool {
    matches!(ch, 'A'..='Z' | '0'..='9' | '_')
}
