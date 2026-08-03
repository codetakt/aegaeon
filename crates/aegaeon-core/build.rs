use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

fn candidate_from_env(repo_root: &Path) -> Option<(PathBuf, PathBuf)> {
    let override_dir = env::var_os("AEG_VERIFIED_CORE_DIR")?;
    let override_dir = PathBuf::from(override_dir);
    let dir = if override_dir.is_absolute() {
        override_dir
    } else {
        repo_root.join(override_dir)
    };
    let manifest = dir.join("manifest.json");
    let wasm = dir.join("verified_core.wasm");
    if manifest.is_file() && wasm.is_file() {
        Some((manifest, wasm))
    } else {
        None
    }
}

fn candidate_in_dir(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let manifest = dir.join("manifest.json");
    let wasm = dir.join("verified_core.wasm");
    if manifest.is_file() && wasm.is_file() {
        Some((manifest, wasm))
    } else {
        None
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=AEG_VERIFIED_CORE_DIR");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let repo_root = manifest_dir.join("../..");

    let candidates = [
        candidate_from_env(&repo_root),
        candidate_in_dir(&repo_root.join("artifacts/verified-core")),
        // CI/Nix builds may not include gitignored artifacts.
        // Use the checked-in fixture as fallback.
        candidate_in_dir(&repo_root.join("tests/fixtures/verified-core")),
    ];

    let (manifest_path, wasm_path) = candidates.into_iter().flatten().next().unwrap_or_else(|| {
        eprintln!(
            concat!(
                "aegaeon-core: no Verified Core artifact found.\n",
                "Expected one of:\n",
                "- $AEG_VERIFIED_CORE_DIR/{{manifest.json,verified_core.wasm}}\n",
                "- {}/artifacts/verified-core/{{manifest.json,verified_core.wasm}}\n",
                "- {}/tests/fixtures/verified-core/{{manifest.json,verified_core.wasm}}",
            ),
            repo_root.display(),
            repo_root.display()
        );
        process::exit(1);
    });

    println!("cargo:rerun-if-changed={}", manifest_path.display());
    println!("cargo:rerun-if-changed={}", wasm_path.display());

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default());
    let out_manifest = out_dir.join("verified_core_manifest.json");
    let out_wasm = out_dir.join("verified_core.wasm");

    if let Err(err) = fs::copy(&manifest_path, &out_manifest) {
        eprintln!(
            "aegaeon-core: failed to copy manifest.json from {} to {}: {err}",
            manifest_path.display(),
            out_manifest.display()
        );
        process::exit(1);
    }

    if let Err(err) = fs::copy(&wasm_path, &out_wasm) {
        eprintln!(
            "aegaeon-core: failed to copy verified_core.wasm from {} to {}: {err}",
            wasm_path.display(),
            out_wasm.display()
        );
        process::exit(1);
    }

    let embedded_rs = out_dir.join("embedded_verified_core.rs");
    let content = r#"
pub const EMBEDDED_MANIFEST_JSON: &str =
    include_str!(concat!(env!("OUT_DIR"), "/verified_core_manifest.json"));

pub const EMBEDDED_WASM_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/verified_core.wasm"));
"#;
    if let Err(err) = fs::write(&embedded_rs, content.trim_start()) {
        eprintln!(
            "aegaeon-core: failed to write {}: {err}",
            embedded_rs.display()
        );
        process::exit(1);
    }
}
