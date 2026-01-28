{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.aegis.secrets;
  hostname = config.networking.hostName;

  # Script to decrypt a secret with age
  decryptScript = { name, source, target, identity, user, group, permissions }:
    pkgs.writeShellScript "aegis-decrypt-${name}" ''
      set -euo pipefail

      # Create target directory if needed
      TARGET_DIR=$(dirname "${target}")
      if [ ! -d "$TARGET_DIR" ]; then
        mkdir -p "$TARGET_DIR"
        chown ${user}:${group} "$TARGET_DIR"
        chmod 0750 "$TARGET_DIR"
      fi

      # Remove old secret if it exists
      rm -f "${target}"

      # Decrypt
      ${pkgs.age}/bin/age --decrypt \
        --identity "${identity}" \
        --output "${target}" \
        "${source}"

      # Set ownership and permissions
      chown ${user}:${group} "${target}"
      chmod ${permissions} "${target}"
    '';

  # Script to remove a secret
  removeScript = name: target:
    pkgs.writeShellScript "aegis-remove-${name}" ''
      rm -f "${target}"
    '';

  # Generate a systemd service for a secret
  mkSecretService = name: secretCfg: {
    description = "Aegis: decrypt ${name}";
    wantedBy = [ "aegis-phase${toString secretCfg.phase}.target" ];
    before = [ "aegis-phase${toString secretCfg.phase}.target" ];
    after = if secretCfg.phase == 1 then
      [ "local-fs.target" ]
    else
      [ "aegis-phase1.target" ];
    requires = if secretCfg.phase == 1 then
      [ "local-fs.target" ]
    else
      [ "aegis-phase1.target" ];

    restartIfChanged = true;

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = decryptScript {
        inherit name;
        source = secretCfg.source;
        target = secretCfg.target;
        identity = secretCfg.identity;
        user = secretCfg.user;
        group = secretCfg.group;
        permissions = secretCfg.permissions;
      };
      ExecStop = removeScript name secretCfg.target;
    };
  };

  # Secret options submodule
  secretOpts = { name, ... }: {
    options = {
      source = mkOption {
        type = types.path;
        description = "Path to the encrypted .age file.";
      };

      target = mkOption {
        type = types.str;
        description = "Path where the decrypted secret will be placed.";
        default = "/run/aegis/${name}";
      };

      user = mkOption {
        type = types.str;
        description = "Owner of the decrypted file.";
        default = "root";
      };

      group = mkOption {
        type = types.str;
        description = "Group of the decrypted file.";
        default = "root";
      };

      permissions = mkOption {
        type = types.str;
        description = "Permissions for the decrypted file.";
        default = "0400";
      };

      phase = mkOption {
        type = types.enum [ 1 2 ];
        description = ''
          Decryption phase:
          - Phase 1: Uses host master key (for host secrets, role keys, user deployment keys)
          - Phase 2: Uses keys decrypted in phase 1 (for role-specific and user secrets)
        '';
        default = 1;
      };

      identity = mkOption {
        type = types.str;
        description = "Path to the age identity (private key) for decryption.";
        default = cfg.masterKeyPath;
      };

      service = mkOption {
        type = types.str;
        description = "Name of the systemd service for this secret.";
        default = "aegis-secret-${name}";
        readOnly = true;
      };
    };
  };

in {
  options.aegis.secrets = {
    enable = mkEnableOption "Aegis secrets management";

    secretsPath = mkOption {
      type = types.path;
      description = "Path to the aegis-secrets build output for this host.";
      example = "/path/to/aegis-secrets/build/hosts/myhost";
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

    secrets = mkOption {
      type = types.attrsOf (types.submodule secretOpts);
      description = "Secrets to decrypt for this host.";
      default = { };
    };

    # Convenience options for common secret types
    sshKeys = {
      enable = mkEnableOption "SSH key secrets";

      source = mkOption {
        type = types.nullOr types.path;
        description = "Path to encrypted SSH keys file.";
        default = null;
      };
    };

    keytab = {
      enable = mkEnableOption "Kerberos keytab secret";

      source = mkOption {
        type = types.nullOr types.path;
        description = "Path to encrypted keytab file.";
        default = null;
      };

      target = mkOption {
        type = types.str;
        description = "Where to place the decrypted keytab.";
        default = "/run/aegis/keytab";
      };
    };

    roles = mkOption {
      type = types.listOf types.str;
      description =
        "Roles this host has (e.g., kdc, dns). Role keys will be decrypted.";
      default = [ ];
      example = [ "kdc" "dns" ];
    };

    users = mkOption {
      type = types.listOf types.str;
      description = "Users whose secrets should be decrypted on this host.";
      default = [ ];
    };
  };

  config = mkIf cfg.enable {
    # Ensure /run/aegis exists
    systemd.tmpfiles.rules = [
      "d /run/aegis 0755 root root - -"
      "d /run/aegis/users 0755 root root - -"
      "d /run/aegis/roles 0755 root root - -"
    ];

    # Phase 1 target - host secrets decrypted with master key
    systemd.targets.aegis-phase1 = {
      description = "Aegis phase 1: host secrets available";
      wantedBy = [ "multi-user.target" ];
      before = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
    };

    # Phase 2 target - role/user secrets decrypted with phase 1 keys
    systemd.targets.aegis-phase2 = {
      description = "Aegis phase 2: role and user secrets available";
      wantedBy = [ "multi-user.target" ];
      before = [ "multi-user.target" ];
      after = [ "aegis-phase1.target" ];
    };

    # Convenience target for services that need secrets
    systemd.targets.aegis-secrets = {
      description = "Aegis: all secrets available";
      wantedBy = [ "multi-user.target" ];
      after = [ "aegis-phase2.target" ];
      requires = [ "aegis-phase2.target" ];
    };

    # Generate services for all configured secrets
    systemd.services = let
      # User-defined secrets
      secretServices = mapAttrs' (name: secretCfg:
        nameValuePair "aegis-secret-${name}" (mkSecretService name secretCfg))
        cfg.secrets;

      # SSH keys (if enabled)
      sshKeyService =
        optionalAttrs (cfg.sshKeys.enable && cfg.sshKeys.source != null) {
          aegis-ssh-keys = mkSecretService "ssh-keys" {
            source = cfg.sshKeys.source;
            target = "/run/aegis/ssh-keys";
            user = "root";
            group = "root";
            permissions = "0400";
            phase = 1;
            identity = cfg.masterKeyPath;
          };
        };

      # Keytab (if enabled)
      keytabService =
        optionalAttrs (cfg.keytab.enable && cfg.keytab.source != null) {
          aegis-keytab = mkSecretService "keytab" {
            source = cfg.keytab.source;
            target = cfg.keytab.target;
            user = "root";
            group = "root";
            permissions = "0400";
            phase = 1;
            identity = cfg.masterKeyPath;
          };
        };

      # Role key services (phase 1 - decrypt with master key)
      roleKeyServices = listToAttrs (map (role: {
        name = "aegis-role-${role}";
        value = mkSecretService "role-${role}" {
          source = "${cfg.secretsPath}/../roles/${role}.age";
          target = "/run/aegis/roles/${role}";
          user = "root";
          group = "root";
          permissions = "0400";
          phase = 1;
          identity = cfg.masterKeyPath;
        };
      }) cfg.roles);

      # User deployment key services (phase 1 - decrypt with master key)
      userKeyServices = listToAttrs (map (user: {
        name = "aegis-user-key-${user}";
        value = mkSecretService "user-key-${user}" {
          source = "${cfg.secretsPath}/users/${user}/.key.age";
          target = "/run/aegis/users/${user}/.key";
          user = "root";
          group = "root";
          permissions = "0400";
          phase = 1;
          identity = cfg.masterKeyPath;
        };
      }) cfg.users);

    in secretServices // sshKeyService // keytabService // roleKeyServices
    // userKeyServices;

    # Create group for secret access
    users.groups.aegis-secrets = { };
  };
}
