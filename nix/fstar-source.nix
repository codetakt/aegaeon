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
      # These files configure the runner or npm. The F* derivation runs its
      # controls and verifier in Nix, then CI rechecks evidence in the checkout.
      actionDirectories = [
        ".github/actions/setup-component-controller"
        ".github/actions/setup-nix-ci"
      ];
      # Git omits the directory when its last tracked descriptor is deleted.
      # Keep directories containing any neighbor or a non-regular descriptor.
      descriptorOnlyDirectory =
        type == "directory"
        && builtins.elem relative actionDirectories
        && builtins.elem (builtins.readDir path) [
          { }
          { "action.yml" = "regular"; }
        ];
      runnerOrNpmInput =
        type == "regular"
        && (
          (builtins.elem (dirOf relative) actionDirectories && baseNameOf relative == "action.yml")
          || builtins.elem relative [
            "package-lock.json"
            "package.json"
          ]
        );
    in
    !separateDirectory && !unrelatedTest && !descriptorOnlyDirectory && !runnerOrNpmInput;
}
