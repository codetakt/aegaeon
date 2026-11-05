# Fixed unprivileged entry; secret input comes only from systemd credential copies.
{ pkgs, distribution }:
pkgs.runCommand "aegaeon-organization-selected-worker"
  { nativeBuildInputs = with pkgs; [ makeWrapper ]; }
  ''
    mkdir -p "$out/bin" "$out/share/aegaeon"
    cp ${../tests/organizations/legacy_operations/organization_selected_worker.py} "$out/share/aegaeon/organization_selected_worker.py"
    cp ${../tests/organizations/legacy_operations/organization_runtime_stores.json} "$out/share/aegaeon/organization_runtime_stores.json"
    chmod u+w "$out/share/aegaeon/organization_selected_worker.py"
    substituteInPlace "$out/share/aegaeon/organization_selected_worker.py" \
      --replace-fail '@selectedWorkerServer@' '${distribution}/bin/aegaeon-organizations-server'
    makeWrapper ${pkgs.python3}/bin/python3 "$out/bin/aegaeon-organization-selected-worker" \
      --add-flags '-I' --add-flags "$out/share/aegaeon/organization_selected_worker.py"
  ''
