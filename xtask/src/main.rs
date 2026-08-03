#![forbid(unsafe_code)]

use serde_json::json;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

struct DudectHarness {
    name: &'static str,
    sources: &'static [&'static str],
    libs: &'static [&'static str],
}

struct DudectResult {
    name: String,
    state: i64,
    p: f64,
}

const DUDECT_HARNESSES: [DudectHarness; 5] = [
    DudectHarness {
        name: "compare",
        sources: &["tests/constant_time/compare_timing_test.c"],
        libs: &["-lm"],
    },
    DudectHarness {
        name: "hmac",
        sources: &[
            "tests/constant_time/hmac_timing_test.c",
            "c/rsa_signatures.c",
            "c/jws.c",
        ],
        libs: &["-lmbedcrypto", "-lmbedx509", "-lm"],
    },
    DudectHarness {
        name: "ed25519",
        sources: &[
            "tests/constant_time/ed25519_timing_test.c",
            "c/rsa_signatures.c",
        ],
        libs: &["-lmbedcrypto", "-lmbedx509", "-lcrypto", "-lm"],
    },
    DudectHarness {
        name: "rsa",
        sources: &[
            "tests/constant_time/rsa_timing_test.c",
            "c/rsa_signatures.c",
        ],
        libs: &["-lmbedcrypto", "-lmbedx509", "-lcrypto", "-lm"],
    },
    DudectHarness {
        name: "jwe",
        sources: &["tests/constant_time/jwe_timing_test.c", "c/jwe.c"],
        libs: &["-lcrypto", "-lm"],
    },
];

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("dudect") => run_dudect()?,
        Some("kani") => run_kani()?,
        Some("openapi") => run_openapi(args)?,
        _ => {
            eprintln!("usage: cargo xtask [dudect|kani|openapi]");
        }
    }
    Ok(())
}

fn run_openapi(args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    let mut check = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check = true,
            _ => anyhow::bail!("Unknown argument: {arg}"),
        }
    }

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve repository root"))?;
    let out_dir = repo_root.join("generated/openapi");
    fs::create_dir_all(&out_dir)?;

    let management = aegaeon_server::openapi::management_openapi();
    let ops = aegaeon_server::openapi::ops_openapi();

    let management_path = out_dir.join("aegaeon-management-api.v1.json");
    let ops_path = out_dir.join("aegaeon-ops.v1.json");

    let management_json = format!("{}\n", serde_json::to_string_pretty(&management)?);
    let ops_json = format!("{}\n", serde_json::to_string_pretty(&ops)?);

    write_or_check(&management_path, &management_json, check)?;
    write_or_check(&ops_path, &ops_json, check)?;

    if check {
        println!("checked {}", management_path.display());
        println!("checked {}", ops_path.display());
    } else {
        println!("wrote {}", management_path.display());
        println!("wrote {}", ops_path.display());
    }
    Ok(())
}

fn write_or_check(path: &Path, contents: &str, check: bool) -> anyhow::Result<()> {
    if check {
        let existing = fs::read_to_string(path).unwrap_or_default();
        if existing != contents {
            anyhow::bail!("OpenAPI artifact is out of date: {}", path.display());
        }
        return Ok(());
    }
    fs::write(path, contents)?;
    Ok(())
}

fn find_in_path(program: &str) -> anyhow::Result<PathBuf> {
    let path = env::var_os("PATH").ok_or_else(|| anyhow::anyhow!("PATH not set"))?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("{program} not found in PATH");
}

fn pkg_config(args: &[&str]) -> anyhow::Result<Vec<String>> {
    let output = Command::new("pkg-config").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("pkg-config {:?} failed: {}", args, stderr.trim());
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout
        .split_whitespace()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>())
}

fn karamel_cflags() -> anyhow::Result<Vec<String>> {
    let krml_path = find_in_path("krml")?;
    let karamel_prefix = krml_path
        .parent()
        .and_then(|path| path.parent())
        .ok_or_else(|| anyhow::anyhow!("Unexpected krml path layout (expected PREFIX/bin/krml)"))?;
    Ok(vec![format!(
        "-I{}",
        karamel_prefix.join("include").display()
    )])
}

fn compile_dudect_harness(
    harness: &DudectHarness,
    karamel_cflags: &[String],
    evercrypt_cflags: &[String],
    evercrypt_libs: &[String],
) -> anyhow::Result<PathBuf> {
    let bin_path = Path::new("target/ct").join(format!("{}_timing_test", harness.name));
    let status = Command::new("gcc")
        .args(harness.sources)
        .args([
            "-I",
            "include",
            "-I",
            "c",
            "-I",
            "tests/constant_time",
            "-O2",
            "-std=c11",
            "-o",
        ])
        .arg(&bin_path)
        .args(karamel_cflags)
        .args(evercrypt_cflags)
        .args(harness.libs)
        .args(evercrypt_libs)
        .status()?;
    if !status.success() {
        anyhow::bail!("gcc failed for {}", harness.name);
    }
    Ok(bin_path)
}

fn parse_dudect_output(line: &str, harness_name: &str) -> anyhow::Result<DudectResult> {
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(value) => {
            let state = value["state"].as_i64().unwrap_or(1);
            let p = value["p"].as_f64().unwrap_or(0.001);
            println!("dudect {harness_name}: state={state} p={p:.6}");
            if p < 0.01 {
                eprintln!(
                    "WARNING: dudect {harness_name} detected potential timing differences (p={p:.6} < 0.01)"
                );
                eprintln!("This may indicate a timing side channel in the implementation.");
            }
            Ok(DudectResult {
                name: harness_name.to_string(),
                state,
                p,
            })
        }
        Err(error) => anyhow::bail!("Failed to parse dudect output for {harness_name}: {error}"),
    }
}

fn run_dudect_harness(out_dir: &Path, harness: &DudectHarness) -> anyhow::Result<DudectResult> {
    let output_path = out_dir.join(format!("{}.json", harness.name));
    let output = Command::new(compile_dudect_harness(
        harness,
        &karamel_cflags()?,
        &pkg_config(&["--cflags", "evercrypt"])?,
        &pkg_config(&["--libs", "--static", "evercrypt"])?,
    )?)
    .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("dudect test {} failed: {stderr}", harness.name);
    }

    let stdout = String::from_utf8(output.stdout)?;
    let line = stdout
        .lines()
        .last()
        .ok_or_else(|| anyhow::anyhow!("No output from dudect test {}", harness.name))?;
    fs::write(output_path, line)?;
    parse_dudect_output(line, harness.name)
}

fn write_dudect_report(out_dir: &Path, results: &[DudectResult]) -> anyhow::Result<()> {
    let overall_state = i32::from(results.iter().all(|result| result.state == 1));
    let max_p = results
        .iter()
        .map(|result| result.p)
        .fold(0.0_f64, f64::max);

    let mut tests = serde_json::Map::new();
    for result in results {
        tests.insert(
            result.name.clone(),
            json!({"state": result.state, "p": result.p}),
        );
    }

    let report = json!({
        "state": overall_state,
        "p": max_p,
        "tests": tests
    });
    fs::write(out_dir.join("report.json"), report.to_string())?;

    Ok(())
}

fn run_dudect() -> anyhow::Result<()> {
    let out_dir = Path::new("artifacts/ct/dudect");
    fs::create_dir_all(out_dir)?;
    fs::create_dir_all("target/ct")?;

    let mut results = Vec::new();
    for harness in &DUDECT_HARNESSES {
        results.push(run_dudect_harness(out_dir, harness)?);
    }

    write_dudect_report(out_dir, &results)
}

fn run_kani() -> anyhow::Result<()> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve repository root"))?;
    let script = repo_root.join("scripts/kani/run_kani.sh");
    if !script.is_file() {
        anyhow::bail!("Kani runner script not found: {}", script.display());
    }

    let status = Command::new("bash")
        .arg(script)
        .current_dir(repo_root)
        .status()?;
    if !status.success() {
        anyhow::bail!("Kani runner failed with status: {status}");
    }
    Ok(())
}
