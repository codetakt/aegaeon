# Test-only predecessor operator. Not a supported production recovery path.
# Explicit offline operator tool; never launched by a runtime service.
{ pkgs }:
let
  python = pkgs.python3.withPackages (ps: [ ps.psycopg ]);
in
pkgs.runCommand "aegaeon-organization-recovery"
  {
    nativeBuildInputs = with pkgs; [ makeWrapper ];
    passthru = { inherit python; };
  }
  ''
    mkdir -p "$out/bin" "$out/share/aegaeon/scripts/operations" "$out/share/aegaeon/db/organization-witness"
    cp ${../../tests/organizations/legacy_operations/organization_recovery.py} "$out/share/aegaeon/scripts/operations/organization_recovery.py"
    cp ${../../tests/organizations/legacy_operations/organization_recovery_store.py} "$out/share/aegaeon/scripts/operations/organization_recovery_store.py"
    cp ${../../tests/organizations/legacy_operations/organization_recovery_peer.py} "$out/share/aegaeon/scripts/operations/organization_recovery_peer.py"
    cp ${../../tests/organizations/legacy_operations/organization_recovery_resp.py} "$out/share/aegaeon/scripts/operations/organization_recovery_resp.py"
    cp ${../../tests/organizations/legacy_operations/organization_recovery_redis.py} "$out/share/aegaeon/scripts/operations/organization_recovery_redis.py"
    cp ${../../tests/organizations/legacy_operations/organization_recovery_runtime.py} "$out/share/aegaeon/scripts/operations/organization_recovery_runtime.py"
    cp ${../../tests/organizations/legacy_operations/organization_cutover_prepare.py} "$out/share/aegaeon/scripts/operations/organization_cutover_prepare.py"
    cp ${../../tests/organizations/legacy_operations/organization_cutover_plan.py} "$out/share/aegaeon/scripts/operations/organization_cutover_plan.py"
    cp ${../../tests/organizations/legacy_operations/organization_cutover_journal.py} "$out/share/aegaeon/scripts/operations/organization_cutover_journal.py"
    cp ${../../tests/organizations/legacy_operations/organization_cutover_token.py} "$out/share/aegaeon/scripts/operations/organization_cutover_token.py"
    cp ${../../tests/organizations/legacy_operations/organization_cutover_credentials.py} "$out/share/aegaeon/scripts/operations/organization_cutover_credentials.py"
    cp ${../../tests/organizations/legacy_operations/organization_cutover_login.py} "$out/share/aegaeon/scripts/operations/organization_cutover_login.py"
    cp ${../../tests/organizations/legacy_operations/organization_cutover_serving_credentials.py} "$out/share/aegaeon/scripts/operations/organization_cutover_serving_credentials.py"
    cp ${../../tests/organizations/legacy_operations/organization_restore_content.py} "$out/share/aegaeon/scripts/operations/organization_restore_content.py"
    cp ${../../tests/organizations/legacy_operations/organization_restore_inspect.py} "$out/share/aegaeon/scripts/operations/organization_restore_inspect.py"
    cp ${../../db/organization-witness/catalog-v5.sql} "$out/share/aegaeon/db/organization-witness/catalog-v5.sql"
    cp ${../../db/organization-witness/catalog-v16.json} "$out/share/aegaeon/db/organization-witness/catalog-v16.json"
    makeWrapper ${pkgs.coreutils}/bin/timeout "$out/bin/aegaeon-organization-recovery" \
      --add-flags '--signal=TERM --kill-after=5s 125s' \
      --add-flags ${python}/bin/python3 \
      --add-flags '-E -s' \
      --add-flags "$out/share/aegaeon/scripts/operations/organization_recovery.py" \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.systemd ]}
    makeWrapper ${pkgs.coreutils}/bin/timeout "$out/bin/aegaeon-organization-cutover-prepare" \
      --add-flags '--signal=TERM --kill-after=5s 605s' \
      --add-flags ${python}/bin/python3 \
      --add-flags '-E -s' \
      --add-flags "$out/share/aegaeon/scripts/operations/organization_cutover_prepare.py" \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.systemd ]}
    makeWrapper ${pkgs.coreutils}/bin/timeout "$out/bin/aegaeon-organization-restore-inspect" \
      --add-flags '--signal=TERM --kill-after=5s 605s' \
      --add-flags ${python}/bin/python3 \
      --add-flags '-E -s' \
      --add-flags "$out/share/aegaeon/scripts/operations/organization_restore_inspect.py" \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.systemd ]}
  ''
