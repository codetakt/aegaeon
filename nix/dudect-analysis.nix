# Explicit opt-in research analysis. Building this package never runs a timing gate.
{
  lib,
  stdenv,
  python313,
  fetchurl,
  autoPatchelfHook,
  makeWrapper,
  evercryptDist,
  karamel,
  pkg-config,
}:
let
  pythonFlint = python313.pkgs.buildPythonPackage {
    pname = "python-flint";
    version = "0.9.0";
    format = "wheel";
    src = fetchurl {
      url = "https://files.pythonhosted.org/packages/22/7d/a9c0538fbd4444cd6ef98852e1ded2b65caadd255604963d38917358653b/python_flint-0.9.0-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl";
      sha256 = "2a0d8db1fab69104afdc7a9763a690337a1cecafbf476b310f5bcd8ccc97b29b";
    };
    nativeBuildInputs = [ autoPatchelfHook ];
    buildInputs = [ stdenv.cc.cc.lib ];
    pythonImportsCheck = [ "flint" ];
    meta = {
      description = "Pinned Python-FLINT runtime for Dudect interval analysis";
      license = [
        lib.licenses.mit
        lib.licenses.lgpl3Plus
      ];
      platforms = [ "x86_64-linux" ];
    };
  };
  python = python313.withPackages (_: [ pythonFlint ]);
  source = lib.cleanSourceWith {
    src = ../.;
    filter =
      path: type:
      let
        rel = lib.removePrefix "${toString ../.}/" (toString path);
      in
      type == "directory"
      || lib.any (p: lib.hasPrefix p rel) [
        "c/"
        "include/"
        "tests/constant_time/"
        "tests/dudect_analysis/"
      ]
      || builtins.elem rel [
        "flake.lock"
        "nix/dudect.nix"
        "nix/dudect-analysis.nix"
        "nix/evercrypt/dist.nix"
        "nix/evercrypt/sha256-cpu-policy.patch"
        "nix/karamel.nix"
      ];
  };
in
stdenv.mkDerivation {
  pname = "dudect-analysis";
  version = "0.1.0";
  src = source;
  nativeBuildInputs = [
    python
    makeWrapper
    pkg-config
    karamel
  ];
  buildInputs = [ evercryptDist ];
  dontConfigure = true;
  dontBuild = true;
  dontFixup = true;
  installPhase = ''
    runHook preInstall
    target="$out/libexec/dudect-analysis"
    mkdir -p "$target" "$out/bin"
    cp tests/dudect_analysis/*.py "$target/"
    cp tests/dudect_analysis/*.inc "$target/"
    cp tests/dudect_analysis/*.json "$target/"
    cp nix/dudect-analysis.nix "$target/"
    ${python}/bin/python -B - "$target" <<'PY'
    import pathlib, sys
    sys.path.insert(0, 'tests/constant_time')
    from run_candidate import current_sources
    target = pathlib.Path(sys.argv[1]) / 'source'
    for name in current_sources(pathlib.Path('.')):
        dest = target / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(pathlib.Path(name).read_bytes())
    PY
    ${python}/bin/python -B tests/dudect_analysis/package_runtime.py "$target"
    makeWrapper ${python}/bin/python "$out/bin/dudect-analysis" \
      --unset PYTHONPATH --unset PYTHONHOME --unset LD_PRELOAD --unset LD_LIBRARY_PATH \
      --add-flags "-B $target/run_analysis.py"
    runHook postInstall
  '';
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    ${python}/bin/python -B -m unittest discover -s "$out/libexec/dudect-analysis" -p 'test_*.py' -v
    "$out/bin/dudect-analysis" --help
    runHook postInstallCheck
  '';
  passthru = { inherit python pythonFlint; };
  meta = {
    description = "Opt-in source-bound Dudect interval and distributed-calibration analysis";
    license = lib.licenses.asl20;
    platforms = [ "x86_64-linux" ];
    mainProgram = "dudect-analysis";
  };
}
