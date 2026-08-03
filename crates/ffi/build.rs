use std::{
    env,
    error::Error,
    io,
    path::{Path, PathBuf},
};

type BuildResult<T = ()> = Result<T, Box<dyn Error>>;

const BASE_RERUN_FILES: &[&str] = &[
    "cbindgen.toml",
    "src/raw_json_structural.rs",
    "src/tlv.rs",
    "../../c/crypto_bridge.c",
    "../../c/crypto_bridge.h",
    "../../c/hash_computation_runtime.c",
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural.h",
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural_Runtime.h",
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural_Types.h",
];

const REQUIRED_GENERATED: &[&str] = &[
    "../../generated/everparse/DCR.c",
    "../../generated/everparse/DCR.h",
    "../../generated/everparse/DCRWrapper.c",
    "../../generated/everparse/DCRWrapper.h",
    "../../generated/everparse/DcrRegistration.c",
    "../../generated/everparse/DcrRegistration.h",
    "../../generated/everparse/DcrRegistrationWrapper.c",
    "../../generated/everparse/DcrRegistrationWrapper.h",
    "../../generated/everparse/Dpop.c",
    "../../generated/everparse/Dpop.h",
    "../../generated/everparse/DpopWrapper.c",
    "../../generated/everparse/DpopWrapper.h",
    "../../generated/everparse/JoseHeader.c",
    "../../generated/everparse/JoseHeader.h",
    "../../generated/everparse/JoseHeaderWrapper.c",
    "../../generated/everparse/JoseHeaderWrapper.h",
    "../../generated/everparse/IdTokenSchema.c",
    "../../generated/everparse/IdTokenSchema.h",
    "../../generated/everparse/IdTokenSchemaWrapper.c",
    "../../generated/everparse/IdTokenSchemaWrapper.h",
    "../../generated/everparse/LogoutTokenSchema.c",
    "../../generated/everparse/LogoutTokenSchema.h",
    "../../generated/everparse/LogoutTokenSchemaWrapper.c",
    "../../generated/everparse/LogoutTokenSchemaWrapper.h",
    "../../generated/everparse/RequestObjectSchema.c",
    "../../generated/everparse/RequestObjectSchema.h",
    "../../generated/everparse/RequestObjectSchemaWrapper.c",
    "../../generated/everparse/RequestObjectSchemaWrapper.h",
];

const REQUIRED_LOWSTAR_STRUCTURAL: &[&str] = &[
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural.c",
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural.h",
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural_Runtime.c",
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural_Runtime.h",
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural_Types.c",
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural_Types.h",
];

const BASE_C_SOURCES: &[&str] = &[
    "../../c/crypto_bridge.c",
    "../../c/jws.c",
    "../../c/rsa_signatures.c",
    "../../c/jwe.c",
    "../../c/dpop_error.c",
    "../../c/dcr_error.c",
    "../../c/jose_header_error.c",
    "../../c/id_token_error.c",
    "../../c/jose_header_runtime.c",
    "../../c/logout_token_error.c",
    "../../c/request_object_error.c",
    "../../c/json_lowstar_runtime.c",
    "../../generated/lowstar/jose/Jose_HeaderParser_Runtime.c",
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural_Runtime.c",
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural_Types.c",
    "../../generated/lowstar/jose/Jose_LowStar_Json_Structural.c",
    "../../artifacts/karamel/Jose_LowStar_Json_Stack.c",
    "../../generated/lowstar/jose/Jose_Dcr.c",
    "../../generated/everparse/DCR.c",
    "../../generated/everparse/DCRWrapper.c",
    "../../generated/everparse/DcrRegistration.c",
    "../../generated/everparse/DcrRegistrationWrapper.c",
    "../../generated/everparse/Dpop.c",
    "../../generated/everparse/DpopWrapper.c",
    "../../generated/everparse/JoseHeader.c",
    "../../generated/everparse/JoseHeaderWrapper.c",
    "../../generated/everparse/IdTokenSchema.c",
    "../../generated/everparse/IdTokenSchemaWrapper.c",
    "../../generated/everparse/LogoutTokenSchema.c",
    "../../generated/everparse/LogoutTokenSchemaWrapper.c",
    "../../generated/everparse/RequestObjectSchema.c",
    "../../generated/everparse/RequestObjectSchemaWrapper.c",
];

const BASE_INCLUDE_DIRS: &[&str] = &[
    "../../include",
    "../../generated/everparse",
    "../../generated/lowstar/jose",
    "../../generated/lowstar/oidc",
    "../../artifacts/karamel",
];

struct NativeDeps {
    mbed: pkg_config::Library,
    libsodium: Option<pkg_config::Library>,
    evercrypt: pkg_config::Library,
    karamel_prefix: PathBuf,
    karamel_dist: PathBuf,
}

fn other_error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn emit_rerun_if_changed(paths: &[&str]) {
    for path in paths {
        println!("cargo:rerun-if-changed={path}");
    }
}

fn emit_include_paths(paths: &[PathBuf]) {
    for path in paths {
        println!("cargo:include={}", path.display());
    }
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn cargo_manifest_dir() -> BuildResult<PathBuf> {
    env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map_err(|_| {
            other_error("CARGO_MANIFEST_DIR not set (cargo should set this for build scripts)")
                .into()
        })
}

fn generate_cbindgen_header(manifest_dir: &Path) -> BuildResult {
    emit_rerun_if_changed(BASE_RERUN_FILES);

    let out_dir = env::var("OUT_DIR").map_err(|_| other_error("OUT_DIR not set"))?;
    let output = PathBuf::from(out_dir).join("aegaeon_tlv.h");
    let config = cbindgen::Config::from_root_or_default(manifest_dir);
    let bindings = cbindgen::Builder::new()
        .with_crate(manifest_dir)
        .with_config(config)
        .generate()
        .map_err(|error| other_error(format!("Unable to generate FFI header: {error}")))?;
    bindings.write_to_file(&output);

    println!("cargo:warning=Generated {}", output.display());
    Ok(())
}

fn should_skip_native_build() -> bool {
    env::var("CARGO_FEATURE_KANI").is_ok() || env::var("CARGO_CFG_TEST").is_ok()
}

fn emit_fallback_cfg() {
    println!("cargo:rustc-cfg=no_mbedtls");
}

fn probe_native_deps() -> BuildResult<Option<NativeDeps>> {
    let Ok(mbed) = pkg_config::probe_library("mbedtls") else {
        emit_fallback_cfg();
        return Ok(None);
    };
    let libsodium = pkg_config::probe_library("libsodium").ok();
    let Ok(evercrypt) = pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("evercrypt")
    else {
        emit_fallback_cfg();
        return Ok(None);
    };

    let krml_path = find_in_path("krml").ok_or_else(|| {
        other_error(
            "KaRaMeL (krml) not found in PATH. Install KaRaMeL or enter the verification shell.",
        )
    })?;
    let karamel_prefix = krml_path
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| other_error("Unexpected krml path layout (expected PREFIX/bin/krml)"))?;

    emit_include_paths(&mbed.include_paths);
    if let Some(lib) = &libsodium {
        emit_include_paths(&lib.include_paths);
    }
    emit_include_paths(&evercrypt.include_paths);

    Ok(Some(NativeDeps {
        mbed,
        libsodium,
        evercrypt,
        karamel_dist: karamel_prefix.join("lib/krml/dist/generic"),
        karamel_prefix,
    }))
}

fn verify_generated_artefacts(manifest_dir: &Path) -> BuildResult {
    for file in REQUIRED_GENERATED {
        println!("cargo:rerun-if-changed={file}");
        if !manifest_dir.join(file).exists() {
            return Err(other_error(format!(
                "Required EverParse artefact '{file}' is missing. Run scripts/extraction/run_everparse_batch.sh to regenerate it."
            ))
            .into());
        }
    }
    for file in REQUIRED_LOWSTAR_STRUCTURAL {
        println!("cargo:rerun-if-changed={file}");
        if !manifest_dir.join(file).exists() {
            return Err(other_error(format!(
                "Required structural Low* artefact '{file}' is missing. Run scripts/extraction/run_jose_lowstar.sh to regenerate it."
            ))
            .into());
        }
    }
    Ok(())
}

fn configure_opt_level(build: &mut cc::Build) {
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    if profile == "release" {
        build.opt_level(2);
    } else {
        build.opt_level(1);
    }
}

fn add_files(build: &mut cc::Build, manifest_dir: &Path, files: &[&str]) {
    for file in files {
        build.file(manifest_dir.join(file));
    }
}

fn add_include_dirs(build: &mut cc::Build, manifest_dir: &Path, dirs: &[&str]) {
    for dir in dirs {
        build.include(manifest_dir.join(dir));
    }
}

fn configure_base_build(build: &mut cc::Build, manifest_dir: &Path) {
    configure_opt_level(build);
    emit_rerun_if_changed(BASE_C_SOURCES);
    emit_rerun_if_changed(BASE_INCLUDE_DIRS);
    add_files(build, manifest_dir, BASE_C_SOURCES);
    add_include_dirs(build, manifest_dir, BASE_INCLUDE_DIRS);
    build.warnings(false);
}

fn configure_optional_sources(build: &mut cc::Build, manifest_dir: &Path) -> BuildResult {
    if env::var("CARGO_FEATURE_IDTOKEN_RUNTIME").is_ok() {
        let runtime_dir = "../../generated/lowstar/oidc/id_token";
        let runtime_c = format!("{runtime_dir}/IdToken_Low_Runtime.c");
        let runtime_h = format!("{runtime_dir}/IdToken_Low_Runtime.h");
        println!("cargo:rerun-if-changed={runtime_c}");
        println!("cargo:rerun-if-changed={runtime_h}");
        if !manifest_dir.join(&runtime_c).exists() {
            return Err(other_error(format!(
                "IdToken.Low.Runtime artefact '{runtime_c}' is missing. Run scripts/extraction/run_jose_lowstar.sh with IdToken.Low.Runtime enabled."
            ))
            .into());
        }
        build.file(manifest_dir.join(&runtime_c));
        build.include(manifest_dir.join(runtime_dir));
    }

    if env::var("CARGO_FEATURE_LOWSTAR_HASH").is_ok() {
        let hash_dir = "../../generated/lowstar/oidc/hash";
        let hash_c = format!("{hash_dir}/HashComputation_Low.c");
        let hash_h = format!("{hash_dir}/HashComputation_Low.h");
        println!("cargo:rerun-if-changed={hash_c}");
        println!("cargo:rerun-if-changed={hash_h}");
        println!("cargo:rerun-if-changed=../../c/crypto_bridge.c");
        println!("cargo:rerun-if-changed=../../c/crypto_bridge.h");
        if !manifest_dir.join(&hash_c).exists() {
            return Err(other_error(format!(
                "HashComputation.Low artefact '{hash_c}' is missing. Run scripts/extraction/run_jose_lowstar.sh to regenerate it."
            ))
            .into());
        }
        build.file(manifest_dir.join(&hash_c));
        build.include(manifest_dir.join(hash_dir));
        build.file(manifest_dir.join("../../c/hash_computation_runtime.c"));
    }

    Ok(())
}

fn add_karamel_runtime_file(
    build: &mut cc::Build,
    karamel_dist: &Path,
    file_name: &str,
) -> BuildResult {
    let file = karamel_dist.join(file_name);
    if !file.exists() {
        return Err(other_error(format!(
            "KaRaMeL {file_name} not found at {}. Install KaRaMeL or enter the verification shell.",
            file.display()
        ))
        .into());
    }
    build.file(file);
    Ok(())
}

fn configure_runtime_includes(build: &mut cc::Build, deps: &NativeDeps) -> BuildResult {
    let karamel_include = deps.karamel_prefix.join("include");
    let karamel_runtime = deps.karamel_prefix.join("lib/krml/c");

    build.include(&karamel_include);
    build.include(&karamel_runtime);
    build.include(&deps.karamel_dist);
    emit_include_paths(&[
        karamel_include.clone(),
        karamel_runtime.clone(),
        deps.karamel_dist.clone(),
    ]);

    if let Some(lib) = &deps.libsodium {
        for path in &lib.include_paths {
            build.include(path);
        }
    }
    for path in &deps.mbed.include_paths {
        build.include(path);
    }
    for path in &deps.evercrypt.include_paths {
        build.include(path);
    }

    add_karamel_runtime_file(build, &deps.karamel_dist, "fstar_uint32.c")?;
    add_karamel_runtime_file(build, &deps.karamel_dist, "fstar_bytes.c")?;
    Ok(())
}

fn emit_link_instructions(deps: &NativeDeps) {
    for path in &deps.evercrypt.link_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
    for lib in &deps.evercrypt.libs {
        println!("cargo:rustc-link-lib=static={lib}");
    }

    println!("cargo:rustc-link-lib=mbedcrypto");
    println!("cargo:rustc-link-lib=mbedx509");
    if deps.libsodium.is_some() {
        println!("cargo:rustc-link-lib=sodium");
    }
}

fn main() -> BuildResult {
    println!("cargo:rustc-check-cfg=cfg(kani)");
    println!("cargo:rustc-check-cfg=cfg(no_mbedtls)");

    let manifest_dir = cargo_manifest_dir()?;
    generate_cbindgen_header(&manifest_dir)?;

    if should_skip_native_build() {
        return Ok(());
    }

    let Some(native_deps) = probe_native_deps()? else {
        return Ok(());
    };

    verify_generated_artefacts(&manifest_dir)?;

    let mut build = cc::Build::new();
    configure_base_build(&mut build, &manifest_dir);
    configure_optional_sources(&mut build, &manifest_dir)?;
    configure_runtime_includes(&mut build, &native_deps)?;
    build.compile("jose");

    emit_link_instructions(&native_deps);
    Ok(())
}
