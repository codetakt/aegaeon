# Local integration on an owned PostgreSQL supplier; no service/root authority.
{
  pkgs,
  databaseTests,
  distribution,
  server,
  source,
}:
pkgs.writeShellApplication {
  name = "aegaeon-organizations-recovery-integration";
  runtimeInputs = with pkgs; [
    (python3.withPackages (p: [ p.psycopg ]))
    postgresql_18
    atlas
    openssl
    coreutils
  ];
  text = ''
    test "$#" -eq 1
    python3 ${../tests/organizations}/current_runtime.py \
      --root ${source} --package ${databaseTests} --server-package ${distribution} \
      --postgres-bin ${pkgs.postgresql_18}/bin --atlas-bin ${pkgs.atlas}/bin --output "$1"
  '';
}
