{
  lib,
  pkgs,
  mkAppSpec,
  devTools,
  asanDevTools,
  sharedCompilerRt,
  verificationTools,
  verificationRuntimeInputs,
  dockerRuntimeInputs,
  rustToolchain,
  kani',
  verificationFstar,
  verificationZ3,
  karamel,
  everparse,
  python',
}:
let
  perfRuntimeInputs = devTools ++ [ karamel ];
  extractionRuntimeInputs = builtins.filter (
    input: input != pkgs.cargo-vet
  ) verificationRuntimeInputs;

  perfApps = {
    perf-bench = mkAppSpec {
      binName = "aegaeon-perf-bench";
      description = "Run cargo bench.";
      runtimeInputs = perfRuntimeInputs;
      script = ../../scripts/flake/perf_bench.sh;
    };
    perf-coverage = mkAppSpec {
      binName = "aegaeon-perf-coverage";
      description = "Run coverage with llvm-cov.";
      runtimeInputs = perfRuntimeInputs;
      script = ../../scripts/flake/perf_coverage.sh;
    };
    perf-load = mkAppSpec {
      binName = "aegaeon-perf-load";
      description = "Run performance load tests.";
      runtimeInputs = perfRuntimeInputs ++ [ pkgs.curl ];
      script = ../../scripts/flake/perf_load.sh;
    };
  };

  securityApps = {
    security-suite = mkAppSpec {
      binName = "aegaeon-security";
      description = "Run the security suite.";
      runtimeInputs = verificationRuntimeInputs ++ [ pkgs.stdenv.cc ];
      script = ../../scripts/flake/security_suite.sh;
    };
    security-geiger = mkAppSpec {
      binName = "aegaeon-security-geiger";
      description = "Run cargo geiger with filtered output.";
      script = ../../scripts/flake/security_geiger.sh;
    };
    security-sbom = mkAppSpec {
      binName = "aegaeon-security-sbom";
      description = "Run SBOM scan.";
      script = ../../scripts/flake/security_sbom.sh;
    };
    sanitizer-smoke = mkAppSpec {
      binName = "aegaeon-sanitizer-smoke";
      description = "Run sanitizer smoke tests.";
      runtimeInputs = asanDevTools ++ [
        sharedCompilerRt
        pkgs.gcc
      ];
      script = ../../scripts/flake/sanitizer_smoke.sh;
    };
  };

  verificationApps = {
    verify-full = mkAppSpec {
      binName = "aegaeon-verify-full";
      description = "Run full verification pipeline.";
      runtimeInputs = with pkgs; [
        nix
        git
      ];
      script = ../../scripts/flake/verify_full.sh;
    };
    verify-lowstar = mkAppSpec {
      binName = "aegaeon-verify-lowstar";
      description = "Run Low* verification.";
      runtimeInputs = extractionRuntimeInputs;
      script = ../../scripts/flake/verify_lowstar.sh;
    };
    verify-kani = mkAppSpec {
      binName = "verify-kani";
      description = "Run Kani verification harnesses.";
      runtimeInputs = with pkgs; [
        bash
        coreutils
        findutils
        gnugrep
        gawk
        gnused
        which
        kani'
        python3
        rustToolchain
        verificationFstar
        verificationZ3
        karamel
        everparse
        llvmPackages.clang
        llvmPackages.bintools
      ];
      script = ../../scripts/flake/verify_kani_cli.sh;
    };
    verify-jose = mkAppSpec {
      binName = "verify-jose";
      description = "Run JOSE conformance tests.";
      runtimeInputs = verificationRuntimeInputs;
      script = ../../scripts/flake/verify_jose_cli.sh;
    };
  };

  devApps = {
    dev-server = mkAppSpec {
      binName = "aegaeon-dev-server";
      description = "Run the dev server.";
      script = ../../scripts/flake/dev_server.sh;
    };
    build-verified-core = mkAppSpec {
      binName = "aegaeon-build-verified-core";
      description = "Build verified-core WASM artifacts.";
      runtimeInputs = verificationRuntimeInputs;
      script = ../../scripts/flake/build_verified_core.sh;
    };
    dev-services-up = mkAppSpec {
      binName = "aegaeon-dev-services-up";
      description = "Start dev services via docker compose.";
      runtimeInputs = dockerRuntimeInputs;
      script = ../../scripts/flake/dev_services_up.sh;
    };
    dev-services-down = mkAppSpec {
      binName = "aegaeon-dev-services-down";
      description = "Stop dev services via docker compose.";
      runtimeInputs = dockerRuntimeInputs;
      script = ../../scripts/flake/dev_services_down.sh;
    };
    server-container-integration = mkAppSpec {
      binName = "aegaeon-server-container-integration";
      description = "Run server Redis/Postgres ignored integration tests against local containers.";
      runtimeInputs = dockerRuntimeInputs;
      script = ../../scripts/tests/run_server_container_integration.sh;
    };
    dev-watch = mkAppSpec {
      binName = "aegaeon-dev-watch";
      description = "Run cargo watch for dev.";
      script = ../../scripts/flake/dev_watch.sh;
    };
  };

  dockerApps = {
    docker-build = mkAppSpec {
      binName = "aegaeon-docker-build";
      description = "Build the Docker image.";
      runtimeInputs = devTools ++ [
        pkgs.docker-client
        pkgs.nix
        pkgs.gzip
      ];
      script = ../../scripts/flake/docker_build.sh;
    };
    docker-run = mkAppSpec {
      binName = "aegaeon-docker-run";
      description = "Run the Docker image.";
      runtimeInputs = devTools ++ [ pkgs.docker-client ];
      script = ../../scripts/flake/docker_run.sh;
    };
  };

  toolingApps = {
    lint-server-clippy-inventory = mkAppSpec {
      binName = "aegaeon-lint-server-clippy-inventory";
      description = "Run the aegaeon-server Clippy inventory regression gate.";
      runtimeInputs = devTools ++ [ karamel ];
      script = ../../scripts/flake/lint_server_clippy_inventory.sh;
    };
    everparse = mkAppSpec {
      binName = "everparse";
      description = "Run EverParse CLI.";
      runtimeInputs = [
        everparse
        pkgs.fstar
        karamel
        pkgs.z3
      ];
      script = ../../scripts/flake/everparse_cli.sh;
    };
    karamel = mkAppSpec {
      binName = "karamel";
      description = "Run KaRaMeL CLI.";
      runtimeInputs = [
        karamel
        pkgs.fstar
        pkgs.z3
      ];
      script = ../../scripts/flake/karamel_cli.sh;
    };
  };
in
lib.attrsets.mergeAttrsList [
  perfApps
  securityApps
  verificationApps
  devApps
  dockerApps
  toolingApps
]
