# Offline validation binds the actual native distribution; no caller-supplied tool.
{
  pkgs,
  distribution,
  server,
}:
let
  recovery = import ./tests/organizations-legacy-recovery-tool.nix { inherit pkgs; };
  worker = import ./organizations-worker.nix { inherit pkgs distribution; };
in
pkgs.runCommand "aegaeon-organization-cutover"
  {
    nativeBuildInputs = with pkgs; [ makeWrapper ];
  }
  ''
    mkdir -p "$out/bin"
    cp -r ${recovery}/share "$out/share"
    chmod u+w "$out/share/aegaeon/scripts/operations"
    cp ${../tests/organizations/legacy_operations/organization_cutover_validate.py} "$out/share/aegaeon/scripts/operations/organization_cutover_validate.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_validation.py} "$out/share/aegaeon/scripts/operations/organization_cutover_validation.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_phase.py} "$out/share/aegaeon/scripts/operations/organization_cutover_phase.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_epochs.py} "$out/share/aegaeon/scripts/operations/organization_cutover_epochs.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_epoch_inputs.py} "$out/share/aegaeon/scripts/operations/organization_cutover_epoch_inputs.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_epoch_checks.py} "$out/share/aegaeon/scripts/operations/organization_cutover_epoch_checks.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_epoch_native.py} "$out/share/aegaeon/scripts/operations/organization_cutover_epoch_native.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_startup_inputs.py} "$out/share/aegaeon/scripts/operations/organization_cutover_startup_inputs.py"
    cp ${../tests/organizations/legacy_operations/organization_runtime_stores.json} "$out/share/aegaeon/scripts/operations/organization_runtime_stores.json"
    cp ${../tests/organizations/legacy_operations/organization_cutover_activation.py} "$out/share/aegaeon/scripts/operations/organization_cutover_activation.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_activation_phase.py} "$out/share/aegaeon/scripts/operations/organization_cutover_activation_phase.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_serving.py} "$out/share/aegaeon/scripts/operations/organization_cutover_serving.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_serving_checks.py} "$out/share/aegaeon/scripts/operations/organization_cutover_serving_checks.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_serving_phase.py} "$out/share/aegaeon/scripts/operations/organization_cutover_serving_phase.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_serving_recovery.py} "$out/share/aegaeon/scripts/operations/organization_cutover_serving_recovery.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_serving_units.py} "$out/share/aegaeon/scripts/operations/organization_cutover_serving_units.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_startup.py} "$out/share/aegaeon/scripts/operations/organization_cutover_startup.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_startup_manifest.py} "$out/share/aegaeon/scripts/operations/organization_cutover_startup_manifest.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_startup_phase.py} "$out/share/aegaeon/scripts/operations/organization_cutover_startup_phase.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_startup_units.py} "$out/share/aegaeon/scripts/operations/organization_cutover_startup_units.py"
    cp ${../tests/organizations/legacy_operations/organization_cutover_history.py} "$out/share/aegaeon/scripts/operations/organization_cutover_history.py"
    chmod u+w "$out/share/aegaeon/scripts/operations/organization_cutover_validation.py"
    substituteInPlace "$out/share/aegaeon/scripts/operations/organization_cutover_validation.py" \
      --replace-fail '@nativeInspector@' '${distribution}/bin/aegaeon-organization-store-inspect' \
      --replace-fail '@nativeBinary@' '${server}/bin/aegaeon-organization-store-inspect'
    chmod u+w "$out/share/aegaeon/scripts/operations/organization_cutover_epoch_inputs.py"
    substituteInPlace "$out/share/aegaeon/scripts/operations/organization_cutover_epoch_inputs.py" \
      --replace-fail '@epochPreparer@' '${distribution}/bin/aegaeon-organization-epoch-prepare' \
      --replace-fail '@epochBinary@' '${server}/bin/aegaeon-organization-epoch-prepare'
    chmod u+w "$out/share/aegaeon/scripts/operations/organization_cutover_startup_inputs.py"
    substituteInPlace "$out/share/aegaeon/scripts/operations/organization_cutover_startup_inputs.py" \
      --replace-fail '@selectedWorkerLauncher@' '${worker}/bin/aegaeon-organization-selected-worker' \
      --replace-fail '@selectedWorkerServer@' '${distribution}/bin/aegaeon-organizations-server' \
      --replace-fail '@selectedWorkerBinary@' '${server}/bin/aegaeon-organizations-server'
    makeWrapper ${pkgs.coreutils}/bin/timeout "$out/bin/aegaeon-organization-cutover-validate" \
      --add-flags '--signal=TERM --kill-after=5s 605s' \
      --add-flags ${recovery.python}/bin/python3 \
      --add-flags '-E -s' \
      --add-flags "$out/share/aegaeon/scripts/operations/organization_cutover_validate.py" \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.systemd ]}
  ''
