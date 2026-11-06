# Import on a dedicated control-store host. This module never initializes or
# restores a cluster and does not authorize Organizations serving admission.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.aegaeonOrganizationControlStore;
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  absolutePrivatePath = types.strMatching "/[A-Za-z0-9_./-]+";
  login = types.strMatching "[a-z][a-z0-9_]{0,62}";
  network = types.strMatching "[0-9a-fA-F:.]+/[0-9]{1,3}";
  database = "aegaeon_organization_control";
  dataDir = "${cfg.storageRoot}/postgresql";
  allow =
    name: networks:
    lib.concatMapStringsSep "\n" (cidr: "hostssl ${database} ${name} ${cidr} scram-sha-256") networks;
  # Reject missing/rewritten cluster identity before NixOS's normal initdb branch.
  # The anchor is supplied separately from the data volume, never a permissive
  # first-start default. Its custody/rollback exclusion is a deployment premise.
  preflight = pkgs.writeShellScript "aegaeon-control-store-preflight" ''
    set -euo pipefail
    ${pkgs.python3}/bin/python3 -I - ${lib.escapeShellArg cfg.listenAddress} ${
      lib.escapeShellArgs (cfg.runtimeNetworks ++ cfg.maintenanceNetworks)
    } <<'PYCODE'
    import ipaddress
    import sys
    address = ipaddress.ip_address(sys.argv[1])
    mapped = getattr(address, "ipv4_mapped", None)
    if address.is_unspecified or (mapped is not None and mapped.is_unspecified):
        raise SystemExit("control-store wildcard listener refused")
    if any(ipaddress.ip_network(value, strict=False).prefixlen == 0 for value in sys.argv[2:]):
        raise SystemExit("control-store unrestricted source network refused")
    PYCODE
    test -f ${lib.escapeShellArg "${dataDir}/PG_VERSION"}
    test "$(cat ${lib.escapeShellArg "${dataDir}/PG_VERSION"})" = 18
    test -f "$CREDENTIALS_DIRECTORY/cluster-identity"
    expected=$(cat "$CREDENTIALS_DIRECTORY/cluster-identity")
    [[ "$expected" =~ ^[1-9][0-9]{0,19}$ ]]
    actual=$(LC_ALL=C ${pkgs.postgresql_18}/bin/pg_controldata ${lib.escapeShellArg dataDir} | ${pkgs.gnused}/bin/sed -n 's/^Database system identifier: *//p')
    test "$actual" = "$expected"
  '';
in
{
  options.services.aegaeonOrganizationControlStore = {
    enable = mkEnableOption "the isolated Organizations control-store reference service";
    storageRoot = mkOption {
      type = absolutePrivatePath;
      description = "Dedicated persistent mount, excluded from primary/token backup restore operations.";
    };
    clusterIdentityFile = mkOption {
      type = absolutePrivatePath;
      description = "Separately retained PostgreSQL system identifier, recorded at explicit provisioning.";
    };
    certificateFile = mkOption {
      type = absolutePrivatePath;
      description = "Server certificate chain supplied privately outside the Nix store.";
    };
    privateKeyFile = mkOption {
      type = absolutePrivatePath;
      description = "Server TLS key supplied through systemd credentials.";
    };
    listenAddress = mkOption {
      type = types.strMatching "[0-9a-fA-F:.]+";
      description = "Explicit private address of this dedicated host.";
    };
    runtimeLogin = mkOption {
      type = login;
      description = "Previously provisioned runtime-only login; no owner or maintenance membership.";
    };
    maintenanceLogin = mkOption {
      type = login;
      description = "Separate previously provisioned maintenance login.";
    };
    runtimeNetworks = mkOption {
      type = types.nonEmptyListOf network;
      description = "Explicit runtime source networks; default-deny HBA follows these entries.";
    };
    maintenanceNetworks = mkOption {
      type = types.nonEmptyListOf network;
      description = "Explicit operator source networks, separate from runtime credentials.";
    };
  };

  config = mkIf cfg.enable {
    system.build.aegaeonOrganizationControlPreflight = preflight;
    assertions = [
      {
        assertion = cfg.runtimeLogin != cfg.maintenanceLogin;
        message = "Organizations runtime and maintenance logins must differ.";
      }
      {
        assertion =
          !builtins.elem "postgres" [
            cfg.runtimeLogin
            cfg.maintenanceLogin
          ];
        message = "Organizations service connections must not use the database administrator.";
      }
      {
        assertion = lib.all (p: !(lib.hasPrefix "/nix/store/" p)) [
          cfg.storageRoot
          cfg.clusterIdentityFile
          cfg.certificateFile
          cfg.privateKeyFile
        ];
        message = "Organizations state and supplied credential paths must stay outside the Nix store.";
      }
      {
        assertion = !(lib.hasPrefix "${cfg.storageRoot}/" cfg.clusterIdentityFile);
        message = "The control cluster identity anchor must be outside the control data volume.";
      }
      {
        assertion = lib.all (p: !(builtins.elem ".." (lib.splitString "/" p))) [
          cfg.storageRoot
          cfg.clusterIdentityFile
          cfg.certificateFile
          cfg.privateKeyFile
        ];
        message = "Control-store paths must not contain parent traversal.";
      }
      {
        assertion = builtins.match "[0:.]+" cfg.listenAddress == null;
        message = "The control listener must bind an explicit address, not a wildcard.";
      }
      {
        assertion = lib.all (n: builtins.match ".*/0+" n == null) (
          cfg.runtimeNetworks ++ cfg.maintenanceNetworks
        );
        message = "Control-store source networks must not allow every address.";
      }
      {
        assertion =
          let
            settings = config.services.postgresql.settings;
          in
          settings.fsync
          && settings.full_page_writes
          && settings.ssl
          && settings.synchronous_commit == "on"
          && settings.default_transaction_isolation == "read committed"
          && !settings.default_transaction_read_only;
        message = "Control-store live durability, TLS and transaction settings must remain enabled.";
      }
    ];

    services.postgresql = {
      enable = true;
      package = pkgs.postgresql_18;
      inherit dataDir;
      enableTCPIP = true;
      ensureDatabases = lib.mkForce [ ];
      ensureUsers = lib.mkForce [ ];
      initialScript = lib.mkForce null;
      authentication = lib.mkForce ''
        local all postgres peer
        local all all reject
        hostnossl all all 0.0.0.0/0 reject
        hostnossl all all ::/0 reject
        ${allow cfg.runtimeLogin cfg.runtimeNetworks}
        ${allow cfg.maintenanceLogin cfg.maintenanceNetworks}
        host all all 0.0.0.0/0 reject
        host all all ::/0 reject
      '';
      settings = {
        listen_addresses = lib.mkForce cfg.listenAddress;
        ssl = true;
        ssl_min_protocol_version = "TLSv1.2";
        ssl_cert_file = "/run/credentials/postgresql.service/server-certificate";
        ssl_key_file = "/run/credentials/postgresql.service/server-key";
        password_encryption = "scram-sha-256";
        fsync = true;
        full_page_writes = true;
        synchronous_commit = "on";
        default_transaction_isolation = "read committed";
        default_transaction_read_only = false;
        max_connections = 96;
        statement_timeout = "10s";
        lock_timeout = "5s";
        idle_in_transaction_session_timeout = "10s";
        log_statement = "none";
        log_min_error_statement = "panic";
        log_parameter_max_length = 0;
        log_parameter_max_length_on_error = 0;
      };
    };
    systemd.services.postgresql = {
      preStart = lib.mkBefore ''
        ${preflight}
      '';
      unitConfig.AssertPathIsMountPoint = cfg.storageRoot;
      serviceConfig = {
        LoadCredential = [
          "cluster-identity:${cfg.clusterIdentityFile}"
          "server-certificate:${cfg.certificateFile}"
          "server-key:${cfg.privateKeyFile}"
        ];
        TimeoutStartSec = "30s";
        TimeoutStopSec = "30s";
      };
    };
  };
}
