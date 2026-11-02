# Rust Clippy compiles all targets, so retain test fixtures, native/generated
# sources, workflow guards and unknown additions. CI orchestration is checked
# separately and does not participate in these compile-only lint commands.
{ lib, source }:
lib.cleanSourceWith {
  src = source;
  name = "aegaeon-cargo-lint-source";
  filter =
    path: _type:
    let
      root = source.origSrc or source;
      relative = lib.removePrefix "${toString root}/" (toString path);
      excluded = [
        "docs/automation"
        "scripts/ci"
        "tests/ci"
      ];
    in
    !(builtins.any (prefix: relative == prefix || lib.hasPrefix "${prefix}/" relative) excluded);
}
