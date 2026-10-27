# Local to the JOSE Nix check, including dependency preparation. Preserve
# workflow files read by Rust guards, all test/native/generated inputs and
# unknown additions. The excluded orchestration keeps its own CI checks.
{ lib, source }:
lib.cleanSourceWith {
  src = source;
  name = "aegaeon-jose-source";
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
