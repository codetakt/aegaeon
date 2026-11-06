# Current-state activation only; backup/restore remains an operator responsibility.
{ pkgs }:
pkgs.runCommand "aegaeon-organization-operations" { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
  mkdir -p "$out/bin" "$out/share/aegaeon"
  cp ${../scripts/operations/activate-organizations-runtime.sql} "$out/share/aegaeon/activate-organizations-runtime.sql"
  cp ${../scripts/operations/provision-organizations.sql} "$out/share/aegaeon/provision-organizations.sql"
  makeWrapper ${pkgs.postgresql_18}/bin/psql "$out/bin/aegaeon-organization-activate" \
    --add-flags '-X -v ON_ERROR_STOP=1' \
    --add-flags "-f $out/share/aegaeon/activate-organizations-runtime.sql"
''
