# Cache a source-bound build package; timing admission always executes afresh.
{
  lib,
  stdenv,
  python3,
  pkg-config,
  evercryptDist,
  karamel,
}:
let
  src = lib.cleanSourceWith {
    src = ../.;
    filter =
      path: type:
      let
        rel = lib.removePrefix "${toString ../.}/" (toString path);
      in
      type == "directory"
      || lib.any (prefix: lib.hasPrefix prefix rel) [
        "c/"
        "include/"
        "tests/constant_time/"
      ]
      || builtins.elem rel [
        "flake.lock"
        "nix/dudect.nix"
        "nix/evercrypt/dist.nix"
        "nix/karamel.nix"
      ];
  };
in
stdenv.mkDerivation {
  pname = "dudect-check";
  version = "0.2.0";
  inherit src;
  nativeBuildInputs = [
    python3
    pkg-config
    karamel
  ];
  buildInputs = [ evercryptDist ];
  dontConfigure = true;
  dontBuild = true;
  # The package manifest binds the exact executable bytes produced by the compiler.
  dontFixup = true;
  installPhase = ''
    runHook preInstall
    python3 tests/constant_time/run_contract.py --suite nix --build-package "$out"
    runHook postInstall
  '';
  meta = with lib; {
    description = "Source-bound dudect observation executables for Aegaeon";
    license = licenses.asl20;
    platforms = platforms.unix;
  };
}
