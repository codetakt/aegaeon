# These workflow files are read by the runtime fixture guard, not the compiler.
# The test runner retains them in workspace-check-source. Keep every other
# input, including unknown workflow additions, in the compilation source.
{ lib, source }:
lib.cleanSourceWith {
  src = source;
  # Preserve the build directory used by compile-time CARGO_MANIFEST_DIR paths.
  name = "aegaeon-workspace-check-source";
  filter =
    path: _type:
    let
      root = source.origSrc or source;
      relative = lib.removePrefix "${toString root}/" (toString path);
    in
    !(builtins.elem relative [
      ".github/workflows/ci.yml"
      ".github/workflows/oidf-conformance.yml"
      ".github/workflows/performance.yml"
      ".github/workflows/verification.yml"
    ]);
}
