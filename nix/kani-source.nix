# This boundary belongs only to the full-scope Kani derivation. Keep all
# Rust/native/generated inputs, fixtures, evidence configuration and unknown
# paths. The excluded CI and Dudect files retain their existing validation.
{ lib, source }:
lib.cleanSourceWith {
  src = source;
  name = "aegaeon-kani-source";
  filter =
    path: _type:
    let
      root = source.origSrc or source;
      relative = lib.removePrefix "${toString root}/" (toString path);
      excluded = [
        "docs/automation"
        "tests/ci"
        "tests/constant_time"
      ];
    in
    !(builtins.any (prefix: relative == prefix || lib.hasPrefix "${prefix}/" relative) excluded);
}
