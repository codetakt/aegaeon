{ pkgs, tamarinProver }:
pkgs.runCommand "verify-tamarin"
  {
    # Proof computation is reusable only for this complete input set. The
    # hosted wrapper still replays the records against its checkout's registry.
    src = pkgs.lib.fileset.toSource {
      root = ../.;
      fileset = pkgs.lib.fileset.unions [
        ../proofs/tamarin
        ../ci/tamarin_proofs.sh
        ../spec/tamarin-evidence.json
        ../scripts/validation/admit_tamarin_lemmas.py
        ../scripts/flake/verify_tamarin.sh
        ../scripts/verify/verify_tamarin_ci.sh
        ../tests/ci/test_tamarin_admission.py
        ../tests/fixtures/tamarin_admission
      ];
    };
    nativeBuildInputs = with pkgs; [
      bash
      coreutils
      python3
      tamarinProver
      maude
    ];
  }
  ''
    export HOME="$TMPDIR"
    cp -r "$src" source
    chmod -R u+w source
    cd source
    mkdir -p "$out"
    OUT_DIR="$out" ${pkgs.bash}/bin/bash ${../scripts/flake/verify_tamarin.sh}
    touch "$out/success"
  ''
