{ pkgs }:
let
  registerPaths = [
    ../spec/server-assurance-contract.v1.json
    ../spec/sdk-assurance-contract.v1.json
  ];
  registers = map (path: builtins.fromJSON (builtins.readFile path)) registerPaths;
  sources = import ./assurance-source-inventory.nix registers;
  manifest = pkgs.writeText "assurance-standards-manifest.json" (
    builtins.toJSON {
      schema_version = 1;
      registers = map (path: {
        filename = builtins.baseNameOf path;
        sha256 = builtins.hashFile "sha256" path;
      }) registerPaths;
      inherit sources;
    }
  );
in
assert import ./tests/assurance-sources.nix;
pkgs.linkFarm "aegaeon-assurance-standards" (
  map (source: {
    name = source.filename;
    path = pkgs.fetchurl {
      url = source.uri;
      inherit (source) sha256;
    };
  }) sources
  ++ [
    {
      name = "manifest.json";
      path = manifest;
    }
  ]
)
