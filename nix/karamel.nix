{
  lib,
  stdenv,
  fetchFromGitHub,
  ocamlPackages,
  zlib,
  gmp,
  bash,
  fstar,
}:
let
  inherit (ocamlPackages)
    ocaml
    menhir
    menhirLib
    yojson
    base
    fmt
    cmdliner
    re
    stdint
    visitors
    sedlex
    uucp
    uutf
    seq
    wasm
    fix
    process
    pprint
    zarith
    ppx_deriving
    ppx_deriving_yojson
    ppx_sexp_conv
    ppx_derivers
    findlib
    ;
  dunePkg = ocamlPackages.dune_3 or ocamlPackages.dune;
in
stdenv.mkDerivation {
  pname = "karamel";
  version = "2025-10-08";

  src = fetchFromGitHub {
    owner = "FStarLang";
    repo = "karamel";
    rev = "254e099bd586b17461845f6b0cab44c3ef5080e9";
    sha256 = "sha256-+ik3D77Qs4N1ZjyDMmcyZDbG+68uWWlg8Xo7/RlyxvM=";
  };

  buildInputs = [
    ocaml
    dunePkg
    menhir
    menhirLib
    yojson
    base
    fmt
    cmdliner
    re
    stdint
    visitors
    sedlex
    uucp
    uutf
    seq
    wasm
    fix
    process
    pprint
    zarith
    ppx_deriving
    ppx_deriving_yojson
    ppx_sexp_conv
    ppx_derivers
    zlib
    gmp
  ];

  nativeBuildInputs = [
    bash
    findlib
    dunePkg
  ];

  buildPhase = ''
    runHook preBuild
    export HOME="$TMPDIR"
    export DUNE_CACHE=disabled
    make minimal PREFIX=$out

    # Generate .checked files for krmllib modules in dependency order
    echo "[karamel] Generating .checked files for krmllib modules..."
    export FSTAR_HOME="${fstar}"
    cd krmllib

    # Build in dependency order: base modules first, then dependent modules
    # Include both .fst and .fsti files
    ordered_modules=(
      "C.fst"
      "Spec.Loops.fst"
      "C.Loops.fst"
      "FStar.Krml.Endianness.fst"
      "C.Endianness.fst"
      "C.String.fsti"
      "C.String.fst"
      "C.Failure.fst"
    )

    for fst in "''${ordered_modules[@]}"; do
      if [ -f "$fst" ]; then
        echo "[karamel] Checking $fst..."
        "${fstar}/bin/fstar.exe" \
          --include "${fstar}/lib/fstar" \
          --include . \
          --cache_checked_modules \
          --cache_dir . \
          --warn_error -321 \
          "$fst" 2>&1 || echo "Warning: Failed to check $fst (continuing)"
      fi
    done
    cd ..

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin
    install -Dm755 _build/default/src/Karamel.exe $out/bin/krml
    mkdir -p $out/include
    cp -R include/. $out/include/
    mkdir -p $out/lib/krml
    cp -R krmllib/. $out/lib/krml/

    # Install .checked files if they were generated
    if ls krmllib/*.checked 1> /dev/null 2>&1; then
      echo "[karamel] Installing .checked files..."
      cp krmllib/*.checked $out/lib/krml/ || true
    fi

    mkdir -p $out/lib/krml/runtime
    cp -R runtime/. $out/lib/krml/runtime/
    mkdir -p $out/share/krml/examples
    cp test/*.fst $out/share/krml/examples/
    mkdir -p $out/share/krml/misc
    cp -R misc/. $out/share/krml/misc/
    runHook postInstall
  '';

  passthru = {
    inherit ocaml; # expose the OCaml version used
  };

  meta = with lib; {
    homepage = "https://github.com/FStarLang/karamel";
    description = "F*/Low* to C/JS compiler";
    license = licenses.asl20;
    platforms = platforms.unix;
  };
}
