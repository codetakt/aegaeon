{
  pkgs,
  src,
  databaseTests,
  aegaeonServerDistribution,
  nodejsRuntime,
}:
pkgs.runCommand "aegaeon-lti-packaged-runtime"
  {
    nativeBuildInputs = with pkgs; [
      postgresql_18
      redis
      atlas
      python3
      openssl
      coreutils
      nodejsRuntime
    ];
    AEGAEON_CHROMIUM = "${pkgs.chromium}/bin/chromium";
  }
  ''
    set -euo pipefail
    if ! timeout --kill-after=10s 300s python3 ${src}/tests/lti/packaged_runtime.py \
      --root ${src} --package ${databaseTests} \
      --server ${aegaeonServerDistribution} --output "$out"; then
      for log in prepare server journey; do
        if test -f "$out/$log.log"; then tail -n 20 "$out/$log.log"; fi
      done
      exit 1
    fi
  ''
