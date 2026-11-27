# This boundary belongs only to the full-scope Kani derivation. Keep all
# Rust/native/generated inputs, fixtures, evidence configuration and unknown
# paths. The excluded CI and Dudect files retain their existing validation.
{ lib, source }:
lib.cleanSourceWith {
  src = source;
  name = "aegaeon-kani-source";
  filter =
    path: type:
    let
      root = source.origSrc or source;
      relative = lib.removePrefix "${toString root}/" (toString path);
      excluded = [
        "docs/automation"
        "tests/ci"
        "tests/constant_time"
      ];
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
    !descriptorOnlyDirectory
    && !runnerOrNpmInput
    && !(builtins.any (prefix: relative == prefix || lib.hasPrefix "${prefix}/" relative) excluded);
}
