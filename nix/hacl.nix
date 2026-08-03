{
  pkgs ? import <nixpkgs> { },
}:

let
  pinned = pkgs.callPackage ./hacl-star { };
in
pkgs.stdenv.mkDerivation rec {
  pname = "hacl-star";
  inherit (pinned) version src;

  nativeBuildInputs = with pkgs; [
    ocaml
    z3
  ];

  # We only need F* sources, not the full build
  dontBuild = true;

  installPhase = ''
    mkdir -p $out/share/hacl-star/fstar

    # Copy F* specification files
    if [ -d "specs" ]; then
      cp -r specs/* $out/share/hacl-star/fstar/ 2>/dev/null || true
    fi

    # Copy F* code files
    if [ -d "code" ]; then
      cp -r code/* $out/share/hacl-star/fstar/ 2>/dev/null || true
    fi

    # Copy F* library files
    if [ -d "lib" ]; then
      cp -r lib/* $out/share/hacl-star/fstar/ 2>/dev/null || true
    fi

    # Ensure we have the key modules
    echo "Checking installed F* files..."
    if [ -d "$out/share/hacl-star/fstar" ]; then
      find $out/share/hacl-star/fstar -name "*.fst" -o -name "*.fsti" | head -10 || true
    fi

    echo "HACL* F* sources installed to $out/share/hacl-star/fstar"
  '';

  meta = with pkgs.lib; {
    description = "HACL* verified cryptographic library - F* sources";
    homepage = "https://github.com/hacl-star/hacl-star";
    license = licenses.asl20; # Apache 2.0 license
    platforms = platforms.all;
  };
}
