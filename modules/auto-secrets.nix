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
      description = ''
        Additional roles to enable for this host. By default, roles are
        auto-discovered from <buildPath>/roles/*.age — any role key file
        present for this host will be decrypted. Use this to add roles
        beyond what is in the build directory.
      '';
      default = [ ];
    };

    verbose = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Enable verbose output at Nix evaluation time.
        When enabled, prints the list of secret names being configured for this host.
      '';
    };
  };

  config = mkIf cfg.enable {
    aegis.secrets = {
      enable = true;
      dryRun = cfg.dryRun;
      dryRunPath = cfg.dryRunPath;
      secretsPath = cfg.buildPath;
      masterKeyPath = cfg.masterKeyPath;
      roles = unique (cfg.roles
        ++ map (removeSuffix ".age") (findAgeFiles "${cfg.buildPath}/roles"));
      users = cfg.users;
      verbose = cfg.verbose;

      # Auto-discover SSH host key types from ssh_host_*_key.age files
      sshHostKeys =
        let
          allFiles = listDir "${cfg.buildPath}/ssh";
          sshKeyTypes = lib.pipe allFiles [
            (builtins.filter
              (n: builtins.match "ssh_host_.*_key\\.age" n != null))
            (map (n:
              builtins.head (builtins.match "ssh_host_(.*)_key\\.age" n)))
          ];
        in {
          enable = sshKeyTypes != [ ];
          keyTypes = sshKeyTypes;
        };

      # Auto-discover host secrets (excluding SSH host key files handled above)
      secrets = let
        hostSecrets = filter
          (n: builtins.match "ssh_host_.*_key\\.age" n == null)
          (findAgeFiles cfg.buildPath);

        mkHostSecret = filename: {
          name = removeSuffix ".age" filename;
          value = {
            source = "${cfg.buildPath}/${filename}";
            target = "/run/aegis/${removeSuffix ".age" filename}";
            phase = 1;
          };
        };

      in listToAttrs (map mkHostSecret hostSecrets);

      # Keytab
      keytab = {
        enable = builtins.pathExists "${cfg.buildPath}/keytab.age";
        source = mkIf (builtins.pathExists "${cfg.buildPath}/keytab.age")
          "${cfg.buildPath}/keytab.age";
      };
    };
  };
}
