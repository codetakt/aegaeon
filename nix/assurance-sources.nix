{ pkgs }:
let
  registerPaths = [
    ../spec/server-assurance-contract.v1.json
    ../spec/sdk-assurance-contract.v1.json
  ];
  registers = map (path: builtins.fromJSON (builtins.readFile path)) registerPaths;
  sources = import ./assurance-source-inventory.nix registers;
  ltiWrappers = builtins.fromJSON (builtins.readFile ../scripts/validation/lti_source_wrappers.json);
  manifest = pkgs.writeText "assurance-standards-manifest.json" (
    builtins.toJSON {
      schema_version = 1;
      registers = map (path: {
        filename = builtins.baseNameOf path;
        sha256 = builtins.hashFile "sha256" path;
      }) registerPaths;
      inherit sources;
      source_reconstruction = {
        method = "restore-two-volatile-drupal-wrapper-fields-then-verify-original-sha256";
        source_ids = builtins.attrNames ltiWrappers;
        metadata_sha256 = builtins.hashFile "sha256" ../scripts/validation/lti_source_wrappers.json;
      };
    }
  );
in
assert import ./tests/assurance-sources.nix;
pkgs.linkFarm "aegaeon-assurance-standards" (
  map (source: {
    name = source.filename;
    path = pkgs.fetchurl (
      {
        url = source.uri;
        inherit (source) sha256;
      }
      // pkgs.lib.optionalAttrs (builtins.hasAttr source.id ltiWrappers) {
        nativeBuildInputs = [ pkgs.python3 ];
        postFetch = ''
          ${pkgs.python3}/bin/python3 ${../scripts/validation}/restore_lti_source_wrapper.py \
            ${pkgs.lib.escapeShellArg source.id} ${pkgs.lib.escapeShellArg source.sha256} "$out"
        '';
      }
    );
  }) sources
  ++ [
    {
      name = "manifest.json";
      path = manifest;
    }
  ]
)
