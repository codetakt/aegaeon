use std::ffi::OsStr;
use std::fmt::Display;
use std::fs;
use std::path::{Path, PathBuf};

const THIS_TEST_FILE: &str = "process_local_runtime_state_guard_test.rs";

const GUARDED_PROCESS_LOCAL_TYPES: &[&str] = &[
    "AuthCodeStore",
    "AuthSessionStore",
    "ClientRegistry",
    "CsrfTokenStore",
    "DeviceCodeStore",
    "ManagementSessionStore",
    "OidcSessionStore",
    "ParStore",
    "RequestObjectJtiStore",
    "StepUpStore",
    "TokenStore",
    "UpstreamAuthStore",
    "UpstreamLogoutRelayStore",
    "VerificationRateLimiter",
];

const FORBIDDEN_INTEGRATION_RUNTIME_STATE_ENV_MARKERS: &[&str] = &[
    "ClientRegistry::try_with_test_clients(",
    "ClientRegistry::try_with_test_clients_with_assertion_policy(",
];

const SERVER_PROCESS_RUNTIME_GATE_MARKERS: &[&str] = &[
    "skip_without_server_process_runtime(",
    "skip_without_server_process_runtime_with_config(",
];

const FORBIDDEN_AD_HOC_TEST_RUNTIME_BUILD_GATES: &[&str] = &[
    "cfg!(debug_assertions)",
    "cfg!(any(debug_assertions, test))",
    "cfg!(any(test, debug_assertions))",
    "#[cfg(any(test, debug_assertions))]",
];
const FORBIDDEN_PRODUCTION_PROCESS_LOCAL_BACKEND_LABELS: &[&str] =
    &["backend: in-memory", "\"in-memory\""];

const TEST_ONLY_HELPER_API_CFG: &str = "#[cfg(test)]";
const RETIRED_INTEGRATION_FIXTURE_MARKERS: &[&str] = &[
    "aegaeon_integration_test_fixtures",
    "AEGAEON_ENABLE_INTEGRATION_TEST_FIXTURES",
    "aegaeon-runtime-fixture-seed",
    "runtime_fixture_seed",
    "test-helpers",
    "aegaeon-server/test-helpers",
    "db-fixture-seed",
    "test-upstream-http",
    "aegaeon-server/db-fixture-seed",
    "aegaeon-server/test-upstream-http",
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
fn process_local_runtime_state_constructors_are_explicit() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let roots = [manifest_dir.join("src"), manifest_dir.join("tests")];
    let mut findings = Vec::new();

    for path in rust_sources(&roots)? {
        let source = fs::read_to_string(&path).test_context(&format!(
            "Rust source should be readable: {}",
            path.display()
        ))?;
        for type_name in GUARDED_PROCESS_LOCAL_TYPES {
            collect_forbidden_calls(&mut findings, &path, &source, type_name);
            collect_forbidden_default_impls(&mut findings, &path, &source, type_name);
            collect_forbidden_new_methods(&mut findings, &path, &source, type_name);
        }
    }

    assert!(
        findings.is_empty(),
        "process-local runtime state constructors must stay explicit:\n{}",
        findings.join("\n")
    );
    Ok(())
}

#[test]
fn process_local_test_helper_apis_are_not_exposed_in_release_builds() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let roots = [manifest_dir.join("src")];
    let mut findings = Vec::new();

    for path in rust_sources(&roots)? {
        let source = fs::read_to_string(&path).test_context(&format!(
            "Rust source should be readable: {}",
            path.display()
        ))?;
        let mut previous_lines = Vec::<&str>::new();
        for (line_index, line) in source.lines().enumerate() {
            if public_test_helper_api_requires_cfg_gate(line)
                && !has_test_cfg_gate(previous_lines.iter().rev().take(8).copied())
            {
                findings.push(format!(
                    "{}:{}: test helper API must have `{}`",
                    path.display(),
                    line_index + 1,
                    TEST_ONLY_HELPER_API_CFG
                ));
            }
            previous_lines.push(line);
        }
    }

    assert!(
        findings.is_empty(),
        "process-local test helper APIs must be cfg-gated out of release builds:\n{}",
        findings.join("\n")
    );
    Ok(())
}

#[test]
fn standalone_refresh_mutation_helpers_are_not_exposed_in_release_builds() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let checks = [
        (
            manifest_dir.join("src/authcode/store/refresh_rotation.rs"),
            "pub fn try_bind_refresh_access(",
        ),
        (
            manifest_dir.join("src/authcode/store/refresh_rotation.rs"),
            "pub fn try_rotate_refresh_token(",
        ),
        (
            manifest_dir.join("src/authcode/store/redis_backend/rotation.rs"),
            "pub(in crate::authcode::store) fn rotate_refresh_token(",
        ),
        (
            manifest_dir.join("src/authcode/store/redis_backend/writes.rs"),
            "pub(in crate::authcode::store) fn bind_refresh_access(",
        ),
    ];
    let mut findings = Vec::new();

    for (path, marker) in checks {
        let source = fs::read_to_string(&path).test_context(&format!(
            "Rust source should be readable: {}",
            path.display()
        ))?;
        let lines = source.lines().collect::<Vec<_>>();
        for (line_index, line) in lines.iter().enumerate() {
            if line.contains(marker)
                && !has_test_cfg_gate(lines[..line_index].iter().rev().take(8).copied())
            {
                findings.push(format!(
                    "{}:{}: standalone refresh mutation helper `{marker}` must have `{}`",
                    path.display(),
                    line_index + 1,
                    TEST_ONLY_HELPER_API_CFG
                ));
            }
        }
    }

    assert!(
        findings.is_empty(),
        "standalone refresh mutation helpers must remain test-only; production refresh flows use atomic grant commits:\n{}",
        findings.join("\n")
    );
    Ok(())
}

#[test]
fn test_runtime_build_gates_use_central_helper() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let roots = [manifest_dir.join("src"), manifest_dir.join("tests")];
    let mut findings = Vec::new();

    for path in rust_sources(&roots)? {
        let source = fs::read_to_string(&path).test_context(&format!(
            "Rust source should be readable: {}",
            path.display()
        ))?;
        for marker in FORBIDDEN_AD_HOC_TEST_RUNTIME_BUILD_GATES {
            collect_marker_findings(&mut findings, &path, &source, 0, marker, |_, _| true);
        }
    }

    assert!(
        findings.is_empty(),
        "test-runtime build gates must use config::test_runtime_helpers_allowed_by_build:\n{}",
        findings.join("\n")
    );
    Ok(())
}

#[test]
fn integration_tests_do_not_use_env_seeded_runtime_state_helpers() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let roots = [manifest_dir.join("tests")];
    let mut findings = Vec::new();

    for path in rust_sources(&roots)? {
        if path.file_name().and_then(OsStr::to_str) == Some("runtime_state_test_env.rs") {
            continue;
        }
        let source = fs::read_to_string(&path).test_context(&format!(
            "integration test source should be readable: {}",
            path.display()
        ))?;
        for marker in FORBIDDEN_INTEGRATION_RUNTIME_STATE_ENV_MARKERS {
            collect_marker_findings(&mut findings, &path, &source, 0, marker, |_, _| true);
        }
    }

    assert!(
        findings.is_empty(),
        "integration tests must use explicit process-local stores or typed DB-backed runtime setup:\n{}",
        findings.join("\n")
    );
    Ok(())
}

#[test]
fn server_process_integration_tests_require_shared_runtime_gate() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let roots = [manifest_dir.join("tests")];
    let mut findings = Vec::new();

    for path in rust_sources(&roots)? {
        let source = fs::read_to_string(&path).test_context(&format!(
            "integration test source should be readable: {}",
            path.display()
        ))?;
        if source.contains("CARGO_BIN_EXE_aegaeon-server")
            && !SERVER_PROCESS_RUNTIME_GATE_MARKERS
                .iter()
                .any(|marker| source.contains(marker))
        {
            findings.push(format!(
                "{}: server binary integration test lacks a DB+Redis runtime gate",
                path.display()
            ));
        }
    }

    assert!(
        findings.is_empty(),
        "server binary integration tests must skip explicitly when PostgreSQL or Redis-backed runtime state is not configured:\n{}",
        findings.join("\n")
    );
    Ok(())
}

#[test]
fn production_process_local_backend_labels_are_explicit() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let roots = [manifest_dir.join("src")];
    let mut findings = Vec::new();

    for path in rust_sources(&roots)? {
        let source = fs::read_to_string(&path).test_context(&format!(
            "Rust source should be readable: {}",
            path.display()
        ))?;
        let source = production_source(&source);
        for marker in FORBIDDEN_PRODUCTION_PROCESS_LOCAL_BACKEND_LABELS {
            collect_marker_findings(&mut findings, &path, source, 0, marker, |_, _| true);
        }
    }

    assert!(
        findings.is_empty(),
        "production runtime-state fallback labels must not remain after shared-store hardening:\n{}",
        findings.join("\n")
    );
    Ok(())
}

#[test]
fn retired_integration_fixture_surface_is_absent() -> TestResult {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut findings = Vec::new();
    for path in [
        manifest_dir.join("build.rs"),
        manifest_dir.join("src/bin/aegaeon-runtime-fixture-seed.rs"),
        manifest_dir.join("src/runtime_fixture_seed.rs"),
        manifest_dir.join("src/runtime_fixture_seed"),
    ] {
        if path.exists() {
            findings.push(format!(
                "{}: retired fixture surface must not exist",
                path.display()
            ));
        }
    }

    let checked_paths = [
        manifest_dir.join("Cargo.toml"),
        manifest_dir.join("src/lib.rs"),
        manifest_dir.join("src/web/upstream_metadata.rs"),
        manifest_dir.join("../../.github/workflows/ci.yml"),
        manifest_dir.join("../../.github/workflows/oidf-conformance.yml"),
        manifest_dir.join("../../.github/workflows/performance.yml"),
        manifest_dir.join("../../.github/workflows/verification.yml"),
        manifest_dir.join("../../Dockerfile"),
        manifest_dir.join("../../nix/flake/checks.nix"),
        manifest_dir.join("../../nix/flake/app-specs.nix"),
        manifest_dir.join("../../scripts/perf/run_load_tests.sh"),
        manifest_dir.join("../../scripts/oidf_conformance/run_oauth2_suite.sh"),
        manifest_dir.join("../../scripts/security/run_security_suite.sh"),
    ];

    for path in checked_paths {
        let source = fs::read_to_string(&path).test_context(&format!(
            "fixture boundary source should be readable: {}",
            path.display()
        ))?;
        for marker in RETIRED_INTEGRATION_FIXTURE_MARKERS {
            if source.contains(marker) {
                findings.push(format!(
                    "{}: retired integration fixture marker `{marker}` must not remain",
                    path.display()
                ));
            }
        }
    }

    assert!(
        findings.is_empty(),
        "retired integration fixture surface must be absent:\n{}",
        findings.join("\n")
    );
    Ok(())
}

fn rust_sources(roots: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for root in roots {
        collect_rust_sources(root, &mut files)?;
    }
    files.sort();
    Ok(files)
}

fn production_source(source: &str) -> &str {
    source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or(source)
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) -> TestResult {
    for entry in fs::read_dir(dir).test_context("source directory should be readable")? {
        let entry = entry.test_context("source directory entry should be readable")?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == OsStr::new("rs"))
            && path.file_name().and_then(OsStr::to_str) != Some(THIS_TEST_FILE)
        {
            out.push(path);
        }
    }
    Ok(())
}

fn collect_forbidden_calls(findings: &mut Vec<String>, path: &Path, source: &str, type_name: &str) {
    for method in ["new", "default"] {
        let marker = format!("{type_name}::{method}(");
        collect_marker_findings(findings, path, source, 0, &marker, |source, offset| {
            is_identifier_boundary(source, offset)
        });
    }
}

fn collect_forbidden_default_impls(
    findings: &mut Vec<String>,
    path: &Path,
    source: &str,
    type_name: &str,
) {
    let marker = format!("impl Default for {type_name}");
    collect_marker_findings(findings, path, source, 0, &marker, |source, offset| {
        is_identifier_boundary(source, offset)
    });
}

fn collect_forbidden_new_methods(
    findings: &mut Vec<String>,
    path: &Path,
    source: &str,
    type_name: &str,
) {
    for block in impl_blocks(source, type_name) {
        for marker in ["fn new(", "fn default("] {
            collect_marker_findings(
                findings,
                path,
                block.body,
                block.line_offset,
                marker,
                is_method_definition_boundary,
            );
        }
    }
}

fn collect_marker_findings(
    findings: &mut Vec<String>,
    path: &Path,
    source: &str,
    line_offset: usize,
    marker: &str,
    accepts: impl Fn(&str, usize) -> bool,
) {
    let mut cursor = 0usize;
    while let Some(found) = source[cursor..].find(marker) {
        let offset = cursor + found;
        if accepts(source, offset) {
            findings.push(format!(
                "{}:{}: forbidden `{}`",
                path.display(),
                line_offset + line_number(source, offset),
                marker
            ));
        }
        cursor = offset + marker.len();
    }
}

struct ImplBlock<'a> {
    body: &'a str,
    line_offset: usize,
}

fn impl_blocks<'a>(source: &'a str, type_name: &str) -> Vec<ImplBlock<'a>> {
    let marker = format!("impl {type_name}");
    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    while let Some(found) = source[cursor..].find(&marker) {
        let offset = cursor + found;
        cursor = offset + marker.len();
        if !is_identifier_boundary(source, offset) {
            continue;
        }
        let Some(open_brace) = source[cursor..].find('{').map(|idx| cursor + idx) else {
            continue;
        };
        let Some(close_brace) = matching_brace(source, open_brace) else {
            continue;
        };
        blocks.push(ImplBlock {
            body: &source[open_brace + 1..close_brace],
            line_offset: source[..open_brace + 1]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
        });
        cursor = close_brace + 1;
    }
    blocks
}

fn matching_brace(source: &str, open_brace: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, ch) in source[open_brace..].char_indices() {
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open_brace + idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn is_identifier_boundary(source: &str, offset: usize) -> bool {
    source[..offset]
        .chars()
        .next_back()
        .is_none_or(|ch| !is_identifier_char(ch))
}

fn is_method_definition_boundary(source: &str, offset: usize) -> bool {
    source[..offset]
        .chars()
        .rev()
        .find(|ch| !ch.is_whitespace())
        .is_none_or(|ch| matches!(ch, ';' | '{' | '}'))
}

fn line_number(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RustVisibility {
    Public,
    Restricted,
}

fn public_test_helper_api_requires_cfg_gate(line: &str) -> bool {
    let Some((visibility, function_name)) = public_function_signature(line) else {
        return false;
    };
    match visibility {
        RustVisibility::Public | RustVisibility::Restricted => {
            function_name.starts_with("new_process_local")
        }
    }
}

fn public_function_signature(line: &str) -> Option<(RustVisibility, &str)> {
    let after_pub = line.trim_start().strip_prefix("pub")?;
    let (visibility, after_visibility) =
        if let Some(after_visibility) = after_pub.strip_prefix(" fn ") {
            (RustVisibility::Public, after_visibility)
        } else if let Some(after_restricted_visibility) = after_pub.strip_prefix('(') {
            let close_visibility = after_restricted_visibility.find(')')?;
            let after_visibility = after_restricted_visibility[close_visibility + 1..]
                .trim_start()
                .strip_prefix("fn ")?;
            (RustVisibility::Restricted, after_visibility)
        } else {
            return None;
        };
    let function_name = after_visibility
        .split(|ch| !is_identifier_char(ch))
        .next()
        .filter(|candidate| !candidate.is_empty())?;
    Some((visibility, function_name))
}

fn has_test_cfg_gate<'a>(lines: impl IntoIterator<Item = &'a str>) -> bool {
    lines
        .into_iter()
        .any(|candidate| candidate.trim() == TEST_ONLY_HELPER_API_CFG)
}

const fn is_identifier_char(ch: char) -> bool {
    matches!(ch, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_')
}
