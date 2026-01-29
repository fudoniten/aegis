{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.aegis.secrets;
  hostname = config.networking.hostName;

  # Compute the host-specific secrets path
  # If secretsRepoPath is set, derive the path; otherwise use secretsPath directly
  hostSecretsPath = if cfg.secretsRepoPath != null then
    "${cfg.secretsRepoPath}/build/hosts/${hostname}"
  else
    cfg.secretsPath;

  # Load the secrets manifest from the build directory (if it exists)
  # This is a plain TOML file that can be read at Nix evaluation time
  manifestPath = "${hostSecretsPath}/secrets.toml";
  manifestExists = builtins.pathExists manifestPath;

  # Parse the manifest, or return empty attrset if not found
  manifest = if manifestExists then
    builtins.fromTOML (builtins.readFile manifestPath)
  else
    { };

  # Helper to get a nested attribute with a default
  getOr = default: path: attrs:
    let
      go = path: attrs:
        if path == [ ] then
          attrs
        else if attrs ? ${head path} then
          go (tail path) attrs.${head path}
        else
          default;
    in go path attrs;

  # Extract SSH host keys config from manifest
  sshHostKeysManifest = getOr null [ "ssh-host-keys" ] manifest;

  # Extract keytab config from manifest
  keytabManifest = getOr null [ "keytab" ] manifest;

  # Extract nexus key config from manifest
  nexusKeyManifest = getOr null [ "nexus-key" ] manifest;

  # Extract extra secrets from manifest
  secretsManifest = getOr { } [ "secrets" ] manifest;

  # Compute actual target path (may be redirected in dry-run mode)
  actualTarget = target:
    if cfg.dryRun then "${cfg.dryRunPath}/${baseNameOf target}" else target;

  # Script to decrypt a secret with age
  decryptScript = { name, source, target, identity, user, group, permissions }:
    let
      realTarget = actualTarget target;
      dryRunPrefix = if cfg.dryRun then "[AEGIS DRY-RUN] " else "";
      logTarget = if cfg.dryRun then
        "dry-run: ${realTarget} (would be: ${target})"
      else
        target;
    in pkgs.writeShellScript "aegis-decrypt-${name}" ''
      set -euo pipefail

      echo "${dryRunPrefix}Decrypting ${name} -> ${logTarget}"

      # Create target directory if needed
      TARGET_DIR=$(dirname "${realTarget}")
      if [ ! -d "$TARGET_DIR" ]; then
        mkdir -p "$TARGET_DIR"
        ${
          if cfg.dryRun then
            "# Dry-run: skipping chown/chmod on directory"
          else ''
            chown ${user}:${group} "$TARGET_DIR"
            chmod 0750 "$TARGET_DIR"
          ''
        }
      fi

      # Remove old secret if it exists
      rm -f "${realTarget}"

      # Decrypt
      ${pkgs.age}/bin/age --decrypt \
        --identity "${identity}" \
        --output "${realTarget}" \
        "${source}"

      # Set ownership and permissions
      ${if cfg.dryRun then ''
        # Dry-run: logging intended permissions instead of applying
        echo "${dryRunPrefix}Would set: owner=${user}:${group} mode=${permissions} on ${target}"
        chmod 0400 "${realTarget}"  # Secure the dry-run file at least
      '' else ''
        chown ${user}:${group} "${realTarget}"
        chmod ${permissions} "${realTarget}"
      ''}

      ${if cfg.dryRun then ''
        echo "${dryRunPrefix}Secret ${name} validated successfully (dry-run mode)"
      '' else
        ""}
    '';

  # Script to remove a secret
  removeScript = name: target:
    let realTarget = actualTarget target;
    in pkgs.writeShellScript "aegis-remove-${name}" ''
      rm -f "${realTarget}"
    '';

  # Script to decrypt all user secrets from manifest
  # This reads the manifest to get actual secret names and targets
  userSecretsScript = username: userSecretsPath:
    let
      dryRunPrefix = if cfg.dryRun then "[AEGIS DRY-RUN] " else "";
      baseTarget = if cfg.dryRun then
        "${cfg.dryRunPath}/users/${username}"
      else
        "/run/aegis/users/${username}";
    in pkgs.writeShellScript "aegis-user-secrets-${username}" ''
      set -euo pipefail

      USER_KEY="/run/aegis/users/${username}/.key"
      MANIFEST_ENC="${userSecretsPath}/manifest.age"
      SECRETS_DIR="${userSecretsPath}/secrets"
      TARGET_DIR="${baseTarget}"

      echo "${dryRunPrefix}Decrypting secrets for user ${username}"

      # Check user key exists
      if [ ! -f "$USER_KEY" ]; then
        echo "ERROR: User deployment key not found: $USER_KEY"
        exit 1
      fi

      # Create target directories
      mkdir -p "$TARGET_DIR/env"
      mkdir -p "$TARGET_DIR/files"
      ${if cfg.dryRun then
        ""
      else ''
        chown ${username}:${username} "$TARGET_DIR" "$TARGET_DIR/env" "$TARGET_DIR/files"
        chmod 0700 "$TARGET_DIR" "$TARGET_DIR/env" "$TARGET_DIR/files"
      ''}

      # Decrypt manifest to temp file
      MANIFEST_TMP=$(mktemp)
      trap "rm -f $MANIFEST_TMP" EXIT

      if [ -f "$MANIFEST_ENC" ]; then
        ${pkgs.age}/bin/age --decrypt \
          --identity "$USER_KEY" \
          --output "$MANIFEST_TMP" \
          "$MANIFEST_ENC"
      else
        echo "WARNING: No manifest found at $MANIFEST_ENC"
        exit 0
      fi

      # Parse manifest and decrypt each secret
      # Manifest format (YAML):
      #   secrets:
      #     <hashed_name>.age:
      #       name: <actual_name>
      #       type: env|file
      #       target: <optional target path for files>

      ${pkgs.yq-go}/bin/yq e '.secrets | to_entries | .[] | [.key, .value.name, .value.type, .value.target // ""] | @tsv' "$MANIFEST_TMP" | \
      while IFS=$'\t' read -r hashed_file actual_name secret_type target_path; do
        SOURCE_FILE="$SECRETS_DIR/$hashed_file"
        
        if [ ! -f "$SOURCE_FILE" ]; then
          echo "WARNING: Secret file not found: $SOURCE_FILE (for $actual_name)"
          continue
        fi
        
        # Determine target based on type
        if [ "$secret_type" = "env" ]; then
          TARGET_FILE="$TARGET_DIR/env/$actual_name"
        elif [ "$secret_type" = "file" ] && [ -n "$target_path" ]; then
          # For files with explicit target, use that (but redirect in dry-run)
          ${
            if cfg.dryRun then ''
              TARGET_FILE="$TARGET_DIR/files/$actual_name"
              echo "${dryRunPrefix}Would place $actual_name at $target_path"
            '' else ''
              TARGET_FILE="$target_path"
            ''
          }
        else
          TARGET_FILE="$TARGET_DIR/files/$actual_name"
        fi
        
        # Create target directory if needed
        TARGET_PARENT=$(dirname "$TARGET_FILE")
        mkdir -p "$TARGET_PARENT"
        
        # Decrypt
        echo "${dryRunPrefix}Decrypting $actual_name -> $TARGET_FILE"
        ${pkgs.age}/bin/age --decrypt \
          --identity "$USER_KEY" \
          --output "$TARGET_FILE" \
          "$SOURCE_FILE"
        
        ${
          if cfg.dryRun then ''
            chmod 0400 "$TARGET_FILE"
          '' else ''
            chown ${username}:${username} "$TARGET_FILE"
            chmod 0400 "$TARGET_FILE"
          ''
        }
      done

      echo "${dryRunPrefix}User secrets for ${username} decrypted successfully"
    '';

  # Generate systemd service for user secrets (phase 2)
  mkUserSecretsService = username: {
    description = "Aegis: decrypt secrets for user ${username}${
        optionalString cfg.dryRun " (DRY-RUN)"
      }";
    wantedBy = [ "aegis-phase2.target" ];
    before = [ "aegis-phase2.target" ];
    after = [ "aegis-phase1.target" "aegis-user-key-${username}.service" ];
    requires = [ "aegis-phase1.target" "aegis-user-key-${username}.service" ];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart =
        userSecretsScript username "${cfg.secretsPath}/users/${username}";
    } // (if cfg.dryRun then
      { }
    else {
      # Run as the user for proper ownership (in production mode)
      User = username;
      Group = username;
    });
  };

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

    dryRun = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Enable dry-run mode for safe migration testing.

        In dry-run mode:
        - Secrets are decrypted to a separate directory (dryRunPath)
        - Ownership/permissions are logged but not applied
        - Services report success but don't affect production paths

        Set to false for production deployment.
      '';
    };

    dryRunPath = mkOption {
      type = types.str;
      default = "/run/aegis-dry-run";
      description = ''
        Directory for dry-run decryption output.
        Only used when dryRun = true.
      '';
    };

    secretsRepoPath = mkOption {
      type = types.nullOr types.path;
      description = ''
        Path to the aegis-secrets repository or its build output.

        When set, secretsPath is automatically computed as:
          ''${secretsRepoPath}/build/hosts/''${networking.hostName}

        This is the recommended way to configure aegis - just point to the
        repo and it will find the right host's secrets automatically.

        Example (in a flake):
          aegis.secrets = {
            enable = true;
            secretsRepoPath = inputs.aegis-secrets;
            masterKeyPath = "/state/master-key/key";
          };
      '';
      default = null;
      example = "/path/to/aegis-secrets";
    };

    secretsPath = mkOption {
      type = types.path;
      description = ''
        Path to the aegis-secrets build output for this specific host.

        Usually you should set secretsRepoPath instead and let this be
        computed automatically. Only set this directly if you have a
        non-standard directory structure.
      '';
      default = hostSecretsPath;
      defaultText = literalExpression
        ''"''${secretsRepoPath}/build/hosts/''${networking.hostName}"'';
      example = "/path/to/aegis-secrets/build/hosts/myhost";
    };

    masterKeyPath = mkOption {
      type = types.str;
      description = ''
        Path to the host's master key (private key) for decryption.

        This is the key Aegis uses to decrypt secrets. It's typically an
        SSH ed25519 private key stored on persistent storage.

        NOTE: This is NOT an OpenSSH host key! This is the master key used
        specifically for Aegis secret decryption. The OpenSSH host keys are
        stored encrypted using this master key and decrypted at boot.
      '';
      example = "/state/master-key/key";
    };

    secrets = mkOption {
      type = types.attrsOf (types.submodule secretOpts);
      description = "Secrets to decrypt for this host.";
      default = { };
    };

    # Convenience options for common secret types
    sshHostKeys = {
      enable = mkEnableOption "SSH host key secrets (for OpenSSH server)";

      source = mkOption {
        type = types.nullOr types.path;
        description = ''
          Path to encrypted SSH host keys file.

          These are the keys OpenSSH uses to identify the server, NOT the
          master key. They are stored in ssh-host-keys.age.
        '';
        default = null;
      };
    };

    # Backward compatibility - keep sshKeys as alias
    sshKeys = {
      enable =
        mkEnableOption "SSH host key secrets (DEPRECATED: use sshHostKeys)";

      source = mkOption {
        type = types.nullOr types.path;
        description =
          "Path to encrypted SSH keys file (DEPRECATED: use sshHostKeys).";
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

    # =========================================================================
    # Manifest data (read-only, loaded from secrets.toml)
    # These can be referenced in NixOS config to get target paths etc.
    # =========================================================================

    manifest = {
      loaded = mkOption {
        type = types.bool;
        description = "Whether a secrets.toml manifest was found and loaded.";
        default = manifestExists;
        readOnly = true;
      };

      sshHostKeys = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            source = mkOption {
              type = types.str;
              description = "Source .age file";
            };
            targetDir = mkOption {
              type = types.str;
              description = "Target directory for SSH keys";
            };
            user = mkOption {
              type = types.str;
              description = "Owner user";
            };
            group = mkOption {
              type = types.str;
              description = "Owner group";
            };
            mode = mkOption {
              type = types.str;
              description = "File permissions";
            };
            keyTypes = mkOption {
              type = types.listOf types.str;
              description = "SSH key types included";
            };
          };
        });
        description = "SSH host keys configuration from manifest.";
        default = if sshHostKeysManifest != null then {
          source = sshHostKeysManifest.source or "ssh-host-keys.age";
          targetDir = sshHostKeysManifest.target_dir or "/etc/ssh";
          user = sshHostKeysManifest.user or "root";
          group = sshHostKeysManifest.group or "root";
          mode = sshHostKeysManifest.mode or "0600";
          keyTypes = sshHostKeysManifest.key_types or [ ];
        } else
          null;
        readOnly = true;
      };

      keytab = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            source = mkOption {
              type = types.str;
              description = "Source .age file";
            };
            target = mkOption {
              type = types.str;
              description = "Target path";
            };
            user = mkOption {
              type = types.str;
              description = "Owner user";
            };
            group = mkOption {
              type = types.str;
              description = "Owner group";
            };
            mode = mkOption {
              type = types.str;
              description = "File permissions";
            };
            encoding = mkOption {
              type = types.nullOr types.str;
              description = "Encoding (e.g., base64)";
            };
          };
        });
        description = "Kerberos keytab configuration from manifest.";
        default = if keytabManifest != null then {
          source = keytabManifest.source or "keytab.age";
          target = keytabManifest.target or "/etc/krb5.keytab";
          user = keytabManifest.user or "root";
          group = keytabManifest.group or "root";
          mode = keytabManifest.mode or "0600";
          encoding = keytabManifest.encoding or null;
        } else
          null;
        readOnly = true;
      };

      nexusKey = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            source = mkOption {
              type = types.str;
              description = "Source .age file";
            };
            target = mkOption {
              type = types.str;
              description = "Target path";
            };
            user = mkOption {
              type = types.str;
              description = "Owner user";
            };
            group = mkOption {
              type = types.str;
              description = "Owner group";
            };
            mode = mkOption {
              type = types.str;
              description = "File permissions";
            };
          };
        });
        description = "Nexus DDNS key configuration from manifest.";
        default = if nexusKeyManifest != null then {
          source = nexusKeyManifest.source or "nexus-key.age";
          target = nexusKeyManifest.target or "/run/aegis/nexus-key";
          user = nexusKeyManifest.user or "root";
          group = nexusKeyManifest.group or "root";
          mode = nexusKeyManifest.mode or "0400";
        } else
          null;
        readOnly = true;
      };

      secrets = mkOption {
        type = types.attrsOf (types.submodule {
          options = {
            source = mkOption {
              type = types.str;
              description = "Source .age file";
            };
            target = mkOption {
              type = types.str;
              description = "Target path";
            };
            user = mkOption {
              type = types.str;
              description = "Owner user";
            };
            group = mkOption {
              type = types.str;
              description = "Owner group";
            };
            mode = mkOption {
              type = types.str;
              description = "File permissions";
            };
          };
        });
        description = "Extra secrets configuration from manifest.";
        default = mapAttrs (name: secretData: {
          source = secretData.source or "secrets/${name}.age";
          target = secretData.target or "/run/aegis/secrets/${name}";
          user = secretData.user or "root";
          group = secretData.group or "root";
          mode = secretData.mode or "0400";
        }) secretsManifest;
        readOnly = true;
      };
    };

    # Auto-configure from manifest
    autoConfigureFromManifest = mkOption {
      type = types.bool;
      description = ''
        Automatically configure secrets from the manifest file.
        When enabled, secrets defined in secrets.toml will be automatically
        set up for decryption without manual configuration.
      '';
      default = false;
    };
  };

  config = mkIf cfg.enable {
    # Warn loudly if dry-run mode is enabled
    warnings = mkIf cfg.dryRun [''
      ╔═══════════════════════════════════════════════════════════════════╗
      ║                    AEGIS DRY-RUN MODE ENABLED                     ║
      ╠═══════════════════════════════════════════════════════════════════╣
      ║  Secrets are being decrypted to ${cfg.dryRunPath}                 ║
      ║  for testing purposes only. Production paths are NOT affected.   ║
      ║                                                                   ║
      ║  To deploy secrets for real, set:                                 ║
      ║    aegis.secrets.dryRun = false;                                  ║
      ╚═══════════════════════════════════════════════════════════════════╝
    ''];

    # Ensure /run/aegis exists (and dry-run path if enabled)
    systemd.tmpfiles.rules = [
      "d /run/aegis 0755 root root - -"
      "d /run/aegis/users 0755 root root - -"
      "d /run/aegis/roles 0755 root root - -"
    ] ++ optionals cfg.dryRun [
      "d ${cfg.dryRunPath} 0755 root root - -"
      "d ${cfg.dryRunPath}/users 0755 root root - -"
      "d ${cfg.dryRunPath}/roles 0755 root root - -"
    ];

    # Phase 1 target - host secrets decrypted with master key
    systemd.targets.aegis-phase1 = {
      description = "Aegis phase 1: host secrets available${
          optionalString cfg.dryRun " (DRY-RUN)"
        }";
      wantedBy = [ "multi-user.target" ];
      before = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
    };

    # Phase 2 target - role/user secrets decrypted with phase 1 keys
    systemd.targets.aegis-phase2 = {
      description = "Aegis phase 2: role and user secrets available${
          optionalString cfg.dryRun " (DRY-RUN)"
        }";
      wantedBy = [ "multi-user.target" ];
      before = [ "multi-user.target" ];
      after = [ "aegis-phase1.target" ];
    };

    # Convenience target for services that need secrets
    systemd.targets.aegis-secrets = {
      description =
        "Aegis: all secrets available${optionalString cfg.dryRun " (DRY-RUN)"}";
      wantedBy = [ "multi-user.target" ];
      after = [ "aegis-phase2.target" ];
      requires = [ "aegis-phase2.target" ];
    };

    # Generate services for all configured secrets
    systemd.services = let
      # User-defined secrets (manual configuration)
      secretServices = mapAttrs' (name: secretCfg:
        nameValuePair "aegis-secret-${name}" (mkSecretService name secretCfg))
        cfg.secrets;

      # SSH host keys for OpenSSH (check both new and deprecated option names)
      sshHostKeySource = if cfg.sshHostKeys.source != null then
        cfg.sshHostKeys.source
      else
        cfg.sshKeys.source;
      sshHostKeyEnabled =
        (cfg.sshHostKeys.enable && cfg.sshHostKeys.source != null)
        || (cfg.sshKeys.enable && cfg.sshKeys.source != null);

      sshKeyService = optionalAttrs sshHostKeyEnabled {
        aegis-ssh-host-keys = mkSecretService "ssh-host-keys" {
          source = sshHostKeySource;
          target = "/run/aegis/ssh-host-keys";
          user = "root";
          group = "root";
          permissions = "0400";
          phase = 1;
          identity = cfg.masterKeyPath;
        };
      };

      # Keytab (if enabled manually)
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

      # User secrets services (phase 2 - decrypt with user deployment key)
      # These read the manifest and decrypt each secret
      userSecretsServices = listToAttrs (map (user: {
        name = "aegis-user-secrets-${user}";
        value = mkUserSecretsService user;
      }) cfg.users);

      # =======================================================================
      # Auto-configured services from manifest
      # =======================================================================

      # SSH host keys from manifest
      manifestSshService = optionalAttrs
        (cfg.autoConfigureFromManifest && cfg.manifest.sshHostKeys != null) {
          aegis-ssh-host-keys = mkSecretService "ssh-host-keys" {
            source = "${cfg.secretsPath}/${cfg.manifest.sshHostKeys.source}";
            # Decrypt to intermediate location, then extract individual keys
            target = "/run/aegis/ssh-host-keys.yaml";
            user = cfg.manifest.sshHostKeys.user;
            group = cfg.manifest.sshHostKeys.group;
            permissions = cfg.manifest.sshHostKeys.mode;
            phase = 1;
            identity = cfg.masterKeyPath;
          };
        };

      # Keytab from manifest
      manifestKeytabService = optionalAttrs
        (cfg.autoConfigureFromManifest && cfg.manifest.keytab != null) {
          aegis-keytab = mkSecretService "keytab" {
            source = "${cfg.secretsPath}/${cfg.manifest.keytab.source}";
            target = cfg.manifest.keytab.target;
            user = cfg.manifest.keytab.user;
            group = cfg.manifest.keytab.group;
            permissions = cfg.manifest.keytab.mode;
            phase = 1;
            identity = cfg.masterKeyPath;
          };
        };

      # Nexus key from manifest
      manifestNexusService = optionalAttrs
        (cfg.autoConfigureFromManifest && cfg.manifest.nexusKey != null) {
          aegis-nexus-key = mkSecretService "nexus-key" {
            source = "${cfg.secretsPath}/${cfg.manifest.nexusKey.source}";
            target = cfg.manifest.nexusKey.target;
            user = cfg.manifest.nexusKey.user;
            group = cfg.manifest.nexusKey.group;
            permissions = cfg.manifest.nexusKey.mode;
            phase = 1;
            identity = cfg.masterKeyPath;
          };
        };

      # Extra secrets from manifest
      manifestSecretServices = optionalAttrs cfg.autoConfigureFromManifest
        (mapAttrs' (name: secretManifest:
          nameValuePair "aegis-secret-${name}" (mkSecretService name {
            source = "${cfg.secretsPath}/${secretManifest.source}";
            target = secretManifest.target;
            user = secretManifest.user;
            group = secretManifest.group;
            permissions = secretManifest.mode;
            phase = 1;
            identity = cfg.masterKeyPath;
          })) cfg.manifest.secrets);

    in secretServices // sshKeyService // keytabService // roleKeyServices
    // userKeyServices // userSecretsServices // manifestSshService
    // manifestKeytabService // manifestNexusService // manifestSecretServices;

    # Create group for secret access
    users.groups.aegis-secrets = { };
  };
}
