# Keep proof inputs by default. Separate timing tests, automation prose and
# unrelated CI test modules do not participate in the F* build or its controls.
{ lib, source }:
lib.cleanSourceWith {
  src = source;
  name = "aegaeon-fstar-source";
  filter =
    path: type:
    let
      root = source.origSrc or source;
      relative = lib.removePrefix "${toString root}/" (toString path);
      name = baseNameOf relative;
      separateDirectory =
        builtins.any (prefix: relative == prefix || lib.hasPrefix "${prefix}/" relative)
          [
            "docs/automation"
            "tests/constant_time"
          ];
      unrelatedTest =
        type == "regular"
        && dirOf relative == "tests/ci"
        && lib.hasPrefix "test_" name
        && lib.hasSuffix ".py" name
        && !(lib.hasPrefix "test_fstar_" name)
        && name != "test_nix_fstar_inputs.py";
    in
    !separateDirectory && !unrelatedTest;
}
