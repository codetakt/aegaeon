# Only Rust workspace checks use this boundary. Retain complete crate trees,
# workflow guards, documentation read by Rust tests, native/generated sources,
# fixtures, migrations and unknown additions. CI orchestration is checked by
# its own full lanes; this boundary never selects or omits a CI lane.
{ lib, source }:
lib.cleanSourceWith {
  src = source;
  name = "aegaeon-workspace-check-source";
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
