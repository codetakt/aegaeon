# This boundary belongs only to the OpenAPI command and its unit tests.
# Keep unknown inputs, all Rust/native sources, fixtures, configuration and
# generated files. CI orchestration is checked by its existing owners.
{ lib, source }:
lib.cleanSourceWith {
  src = source;
  name = "aegaeon-openapi-source";
  filter =
    path: _type:
    let
      root = source.origSrc or source;
      relative = lib.removePrefix "${toString root}/" (toString path);
      excluded = [
        ".github"
        "ci"
        "scripts/ci"
        "tests/ci"
      ];
    in
    !(builtins.any (prefix: relative == prefix || lib.hasPrefix "${prefix}/" relative) excluded);
}
