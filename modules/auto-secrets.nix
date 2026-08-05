{ config, lib, pkgs, ... }:

# Deprecated compatibility shim.
#
# aegis.autoSecrets used to discover secrets by globbing the build directory,
# ignoring secrets.toml entirely.  That made it a second, divergent source of
# truth: SSH keys landed in /etc/ssh via this module but /run/aegis/ssh via the
# manifest, custom target/user/group/mode were silently discarded, and
# keytab.age got two competing decryption units writing the same path.
#
# aegis.secrets now reads the manifest directly and needs no discovery, so this
# module only forwards its options and warns.

with lib;

let cfg = config.aegis.autoSecrets;

in {
  options.aegis.autoSecrets = {
    enable = mkEnableOption
      "(deprecated) auto-discovery wrapper; use aegis.secrets directly";

    dryRun = mkOption {
      type = types.bool;
      default = false;
      description = "Forwarded to aegis.secrets.dryRun.";
    };

    dryRunPath = mkOption {
      type = types.str;
      default = "/run/aegis-dry-run";
      description = "Forwarded to aegis.secrets.dryRunPath.";
    };

    buildPath = mkOption {
      type = types.path;
      description = ''
        Path to this host's secrets directory.
        Forwarded to aegis.secrets.secretsPath.
      '';
      example = ./path/to/aegis-secrets/deploy/hosts/myhost;
    };

    masterKeyPath = mkOption {
      type = types.str;
      description = "Forwarded to aegis.secrets.masterKeyPath.";
      example = "/state/master-key/key";
    };

    users = mkOption {
      type = types.listOf types.str;
      description = "Forwarded to aegis.secrets.users.";
      default = [ ];
    };

    roles = mkOption {
      type = types.listOf types.str;
      description = ''
        Extra roles beyond those declared in the manifest.
        Forwarded to aegis.secrets.roles.
      '';
      default = [ ];
    };

    verbose = mkOption {
      type = types.bool;
      default = false;
      description = "Forwarded to aegis.secrets.verbose.";
    };
  };

  config = mkIf cfg.enable {
    warnings = [''
      aegis.autoSecrets is deprecated and will be removed.

      It discovered secrets by globbing the build directory and ignored
      secrets.toml, so target paths, ownership and permissions recorded by the
      aegis tools were silently discarded.

      Replace:
        aegis.autoSecrets = {
          enable = true;
          buildPath = "''${inputs.aegis-secrets}/deploy/hosts/''${hostname}";
          masterKeyPath = "...";
          users = [ ... ];
        };

      with:
        aegis.secrets = {
          enable = true;
          secretsRepoPath = inputs.aegis-secrets;
          masterKeyPath = "...";
          users = [ ... ];
        };
    ''];

    aegis.secrets = {
      enable = true;
      dryRun = cfg.dryRun;
      dryRunPath = cfg.dryRunPath;
      secretsPath = cfg.buildPath;
      masterKeyPath = cfg.masterKeyPath;
      users = cfg.users;
      verbose = cfg.verbose;
    } // optionalAttrs (cfg.roles != [ ]) {
      # Only override the manifest-derived default when the user asked for
      # extra roles, so the manifest stays authoritative otherwise.
      roles = unique (cfg.roles ++ config.aegis.secrets.manifest.roles);
    };
  };
}
