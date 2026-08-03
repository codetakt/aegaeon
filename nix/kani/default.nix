{
  pkgs ? import <nixpkgs> { },
}:

# Import and call the package.nix with required dependencies
pkgs.callPackage ./package.nix {
  inherit (pkgs)
    lib
    stdenv
    fetchFromGitHub
    fetchurl
    rustPlatform
    makeWrapper
    autoPatchelfHook
    zlib
    curl
    gcc
    cbmc
    kissat
    z3
    cvc5
    minisat
    pkg-config
    openssl
    python3
    ;
}
