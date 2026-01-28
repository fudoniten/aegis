{ config, lib, pkgs, ... }:

# This module auto-discovers secrets from the aegis-secrets build directory
# and configures them for decryption.

with lib;

let
  cfg = config.aegis.autoSecrets;
  hostname = config.networking.hostName;

  # Read directory contents at evaluation time
  listDir = path:
    if builtins.pathExists path then
      builtins.attrNames (builtins.readDir path)
    else
      [ ];

  # Find .age files in a directory
  findAgeFiles = path: filter (name: hasSuffix ".age" name) (listDir path);

  # Remove .age suffix
  removeSuffix = suffix: name:
    if hasSuffix suffix name then
      substring 0 (stringLength name - stringLength suffix) name
    else
      name;

in {
  options.aegis.autoSecrets = {
    enable = mkEnableOption "Auto-discover secrets from build directory";

    dryRun = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Enable dry-run mode for safe migration testing.
        Secrets are decrypted to a test directory instead of production paths.
        Set to false for production deployment.
      '';
    };

    dryRunPath = mkOption {
      type = types.str;
      default = "/run/aegis-dry-run";
      description = "Directory for dry-run decryption output.";
    };

    buildPath = mkOption {
      type = types.path;
      description = "Path to aegis-secrets build output for this host.";
      example = ./path/to/aegis-secrets/build/hosts/myhost;
    };

    masterKeyPath = mkOption {
      type = types.str;
      description = ''
        Path to the host's master key (private key) for decryption.

        Age can use SSH ed25519 private keys directly - no conversion needed.
        Just point this to your existing SSH host key or master key.
      '';
      example = "/state/master-key/key";
    };

    users = mkOption {
      type = types.listOf types.str;
      description = "Users whose secrets to auto-discover.";
      default = [ ];
    };

    roles = mkOption {
      type = types.listOf types.str;
      description = "Roles this host has.";
      default = [ ];
    };
  };

  config = mkIf cfg.enable {
    aegis.secrets = {
      enable = true;
      dryRun = cfg.dryRun;
      dryRunPath = cfg.dryRunPath;
      secretsPath = cfg.buildPath;
      masterKeyPath = cfg.masterKeyPath;
      roles = cfg.roles;
      users = cfg.users;

      # Auto-discover host secrets
      secrets = let
        hostSecrets = findAgeFiles cfg.buildPath;

        mkHostSecret = filename: {
          name = removeSuffix ".age" filename;
          value = {
            source = "${cfg.buildPath}/${filename}";
            target = "/run/aegis/${removeSuffix ".age" filename}";
            phase = 1;
          };
        };

      in listToAttrs (map mkHostSecret hostSecrets);

      # SSH host keys (for OpenSSH server)
      # Check both old name (ssh-keys.age) and new name (ssh-host-keys.age) for compatibility
      sshKeys = {
        enable = builtins.pathExists "${cfg.buildPath}/ssh-host-keys.age"
          || builtins.pathExists "${cfg.buildPath}/ssh-keys.age";
        source =
          if builtins.pathExists "${cfg.buildPath}/ssh-host-keys.age" then
            "${cfg.buildPath}/ssh-host-keys.age"
          else if builtins.pathExists "${cfg.buildPath}/ssh-keys.age" then
            "${cfg.buildPath}/ssh-keys.age"
          else
            null;
      };

      # Keytab
      keytab = {
        enable = builtins.pathExists "${cfg.buildPath}/keytab.age";
        source = mkIf (builtins.pathExists "${cfg.buildPath}/keytab.age")
          "${cfg.buildPath}/keytab.age";
      };
    };
  };
}
