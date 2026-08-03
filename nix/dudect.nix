# Nix derivation for dudect constant-time verification gate.
# Compiles and runs c/dudect_harness.c; creates a success marker on PASS.
{
  lib,
  stdenv,
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
      type == "directory" || lib.hasPrefix "c/" rel;
  };
in
stdenv.mkDerivation {
  pname = "dudect-check";
  version = "0.1.0";

  inherit src;

  buildPhase = ''
    runHook preBuild
    echo "[dudect] Using EverCrypt dist at ${evercryptDist} ..."
    HACL_INC="${evercryptDist}/include"
    KARAMEL_INC="${karamel}/include"
    KARAMEL_C="${karamel}/lib/krml/c"
    KARAMEL_DIST="${karamel}/lib/krml/dist/generic"
    HACL_LIB="${evercryptDist}/lib"
    echo "[dudect] Compiling harness with HACL* ..."
    $CC -O2 -I c -I "$HACL_INC" -I "$KARAMEL_INC" -I "$KARAMEL_C" -I "$KARAMEL_DIST" -o dudect_harness \
      c/dudect_harness.c -L "$HACL_LIB" -levercrypt -lm
    echo "[dudect] Running harness ..."
    ./dudect_harness
    echo "[dudect] PASS"
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    touch "$out/success"
    runHook postInstall
  '';

  meta = with lib; {
    description = "dudect constant-time verification for Aegaeon crypto primitives";
    license = licenses.asl20;
    platforms = platforms.unix;
  };
}
