{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.aegis.secrets;
  hostname = config.networking.hostName;

  stringPadRight = count: str:
    str + (strings.replicate (count - (stringLength str)) " ");

  # Resolve the host's secrets directory.
  #
  # The generated output directory is called deploy/; build/ is the historical
  # name and is still honoured so an un-migrated aegis-secrets keeps working.
  repoHostPath = repoPath:
    let
      deployPath = "${repoPath}/deploy/hosts/${hostname}";
      legacyPath = "${repoPath}/build/hosts/${hostname}";
    in if builtins.pathExists deployPath then deployPath else legacyPath;

  # Explicit secretsPath wins; otherwise derive from the repo.  Note the
  # ordering: deriving `secretsPath`'s *default* from this value while this
  # value read `cfg.secretsPath` was an infinite recursion whenever neither
  # option was set, which is why the VM tests could never evaluate.
  hostSecretsPath = if cfg.secretsPath != null then
    cfg.secretsPath
  else if cfg.secretsRepoPath != null then
    repoHostPath cfg.secretsRepoPath
  else
    null;

  # The manifest is the single source of truth for what this host gets and
  # where it goes.  It is plain TOML so it can be read at evaluation time.
  manifestPath =
    if hostSecretsPath == null then null else "${hostSecretsPath}/secrets.toml";
  manifestExists = manifestPath != null && builtins.pathExists manifestPath;

  manifest = if manifestExists then
    builtins.fromTOML (builtins.readFile manifestPath)
  else
    { };

  # -------------------------------------------------------------------------
  # Manifest -> normalised secret list
  #
  # Every kind of secret becomes the same shape, so there is exactly one unit
  # generator.  `kind` only distinguishes the few behaviours that genuinely
  # differ: SSH keys have a plaintext .pub sidecar, and legacy keytabs may
  # carry a base64 wrapper.
  # -------------------------------------------------------------------------

  normaliseEntry = { name, kind, entry, defaultTarget ? null, defaultMode ? "0400" }: {
    inherit name kind;
    source = "${hostSecretsPath}/${entry.source}";
    target = entry.target or defaultTarget;
    user = entry.user or "root";
    group = entry.group or "root";
    mode = entry.mode or defaultMode;
    encoding = entry.encoding or null;
    phase = 1;
    identity = cfg.masterKeyPath;
  };

  sshEntries = map (entry:
    let
      targetDir = entry.target_dir or "/etc/ssh";
      stem = entry.target or "ssh_host_${entry.type or "ed25519"}_key";
    in (normaliseEntry {
      name = "ssh-${entry.type or stem}";
      kind = "ssh-host-key";
      inherit entry;
      defaultTarget = "${targetDir}/${stem}";
      defaultMode = "0600";
    }) // {
      target = "${targetDir}/${stem}";
      # The public key ships in the clear alongside the encrypted private key
      pubSource = "${hostSecretsPath}/${
          removeSuffix ".age" entry.source
        }.pub";
      pubTarget = "${targetDir}/${stem}.pub";
      keyType = entry.type or null;
    }) (manifest.ssh-host-keys or [ ]);

  keytabEntries = optional (manifest ? keytab) (normaliseEntry {
    name = "keytab";
    kind = "plain";
    entry = manifest.keytab;
    defaultTarget = "/run/aegis/keytab";
    defaultMode = "0600";
  });

  nexusEntries = optional (manifest ? nexus-key) (normaliseEntry {
    name = "nexus-key";
    kind = "plain";
    entry = manifest.nexus-key;
    defaultTarget = "/run/aegis/nexus-key";
  });

  extraEntries = mapAttrsToList (name: entry:
    normaliseEntry {
      name = "secret-${name}";
      kind = "plain";
      inherit entry;
      defaultTarget = "/run/aegis/secrets/${name}";
    }) (manifest.secrets or { });

  manifestRoles = manifest.roles or [ ];

  roleEntries = map (role: {
    name = "role-${role}";
    kind = "plain";
    source = "${hostSecretsPath}/roles/${role}.age";
    target = "/run/aegis/roles/${role}";
    user = "root";
    group = "root";
    mode = "0400";
    encoding = null;
    phase = 1;
    identity = cfg.masterKeyPath;
  }) cfg.roles;

  userKeyEntries = map (username: {
    name = "user-key-${username}";
    kind = "plain";
    source = "${hostSecretsPath}/users/${username}/.key.age";
    target = "/run/aegis/users/${username}/.key";
    # Owned by the user: the phase-2 unit that consumes it runs as them, and
    # a root-owned 0400 key in a 0750 root directory is unreadable to it.
    user = username;
    group = username;
    mode = "0400";
    encoding = null;
    phase = 1;
    identity = cfg.masterKeyPath;
  }) cfg.users;

  # Secrets declared directly in Nix, for anything the manifest cannot express
  manualEntries = mapAttrsToList (name: secretCfg: {
    inherit name;
    kind = "plain";
    source = toString secretCfg.source;
    target = secretCfg.target;
    user = secretCfg.user;
    group = secretCfg.group;
    mode = secretCfg.permissions;
    encoding = null;
    phase = secretCfg.phase;
    identity = secretCfg.identity;
  }) cfg.secrets;

  allEntries = sshEntries ++ keytabEntries ++ nexusEntries ++ extraEntries
    ++ roleEntries ++ userKeyEntries ++ manualEntries;

  # -------------------------------------------------------------------------
  # Decryption
  # -------------------------------------------------------------------------

  # In dry-run mode the whole tree is relocated under dryRunPath, preserving
  # directory structure.  Flattening to the basename made secrets with the
  # same basename in different directories silently overwrite each other.
  actualTarget = target:
    if cfg.dryRun then "${cfg.dryRunPath}${target}" else target;

  dryRunPrefix = if cfg.dryRun then "[AEGIS DRY-RUN] " else "";

  # Legacy: material written before the tools became binary clean carries a
  # `base64:` sentinel.  Nothing writes it any more, but a keytab encrypted by
  # the old tooling still needs unwrapping, and the module used to ignore the
  # manifest's `encoding` field entirely -- deploying the literal string
  # "base64:AAAA..." instead of a keytab.
  decodeCommand = encoding: path:
    if encoding == "base64" then ''
      case "$(${pkgs.coreutils}/bin/head -c 7 "${path}")" in
        "base64:")
          ${pkgs.coreutils}/bin/tail -c +8 "${path}" \
            | ${pkgs.coreutils}/bin/base64 -d > "${path}.decoded"
          ;;
        *)
          ${pkgs.coreutils}/bin/base64 -d < "${path}" > "${path}.decoded"
          ;;
      esac
      mv "${path}.decoded" "${path}"
    '' else
      "";

  mkDecryptScript = entry:
    let
      realTarget = actualTarget entry.target;
      ownership = if cfg.dryRun then ''
        echo "${dryRunPrefix}Would set: owner=${entry.user}:${entry.group} mode=${entry.mode} on ${entry.target}"
        chmod 0400 "${realTarget}"
      '' else ''
        chown ${entry.user}:${entry.group} "${realTarget}"
        chmod ${entry.mode} "${realTarget}"
      '';
    in pkgs.writeShellScript "aegis-decrypt-${entry.name}" ''
      set -euo pipefail

      echo "${dryRunPrefix}Decrypting ${entry.name} -> ${realTarget}"

      TARGET_DIR=$(dirname "${realTarget}")
      if [ ! -d "$TARGET_DIR" ]; then
        mkdir -p "$TARGET_DIR"
        ${optionalString (!cfg.dryRun) ''
          chown ${entry.user}:${entry.group} "$TARGET_DIR"
          chmod 0750 "$TARGET_DIR"
        ''}
      fi

      # Decrypt to a temporary file and move into place, so a failure leaves
      # the previous secret intact rather than deleting it. A rebuild that
      # cannot decrypt should not take the service down.
      TMP=$(mktemp "${realTarget}.XXXXXX")
      trap 'rm -f "$TMP"' EXIT

      ${pkgs.age}/bin/age --decrypt \
        --identity "${entry.identity}" \
        --output "$TMP" \
        "${entry.source}"

      ${decodeCommand entry.encoding "$TMP"}

      mv "$TMP" "${realTarget}"
      trap - EXIT

      ${ownership}

      ${optionalString (entry.kind == "ssh-host-key") ''
        # Public key ships in the clear; keep it beside the private key so
        # sshd and anything reading known_hosts sees a consistent pair.
        install -m 0644 -o ${
          if cfg.dryRun then "root" else entry.user
        } "${entry.pubSource}" "${actualTarget entry.pubTarget}"
      ''}

      ${optionalString cfg.dryRun ''
        echo "${dryRunPrefix}Secret ${entry.name} validated successfully (dry-run mode)"
      ''}
    '';

  mkSecretService = entry: {
    description = "Aegis: decrypt ${entry.name}${
        optionalString cfg.dryRun " (DRY-RUN)"
      }";
    wantedBy = [ "aegis-phase${toString entry.phase}.target" ];
    before = [ "aegis-phase${toString entry.phase}.target" ];
    after = if entry.phase == 1 then
      [ "local-fs.target" ]
    else
      [ "aegis-phase1.target" ];
    requires = if entry.phase == 1 then
      [ "local-fs.target" ]
    else
      [ "aegis-phase1.target" ];

    restartIfChanged = true;
    # No ExecStop that removes the target: with restartIfChanged, a switch
    # would delete the live secret and, if the new unit failed to start, never
    # put it back. The decrypt script replaces the file atomically instead.
    stopIfChanged = false;

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = mkDecryptScript entry;
    };
  };

  # -------------------------------------------------------------------------
  # User secrets (phase 2)
  # -------------------------------------------------------------------------

  userSecretsScript = username:
    let
      userSecretsPath = "${hostSecretsPath}/users/${username}";
      baseTarget = actualTarget "/run/aegis/users/${username}";
    in pkgs.writeShellScript "aegis-user-secrets-${username}" ''
      set -euo pipefail

      USER_KEY="${actualTarget "/run/aegis/users/${username}/.key"}"
      MANIFEST_ENC="${userSecretsPath}/manifest.age"
      SECRETS_DIR="${userSecretsPath}/secrets"
      TARGET_DIR="${baseTarget}"

      echo "${dryRunPrefix}Decrypting secrets for user ${username}"

      if [ ! -r "$USER_KEY" ]; then
        echo "ERROR: User deployment key not readable: $USER_KEY"
        exit 1
      fi

      mkdir -p "$TARGET_DIR/env" "$TARGET_DIR/files"
      chown ${username}:${username} "$TARGET_DIR" "$TARGET_DIR/env" "$TARGET_DIR/files"
      chmod 0700 "$TARGET_DIR" "$TARGET_DIR/env" "$TARGET_DIR/files"

      if [ ! -f "$MANIFEST_ENC" ]; then
        echo "WARNING: No manifest found at $MANIFEST_ENC"
        exit 0
      fi

      MANIFEST_TMP=$(mktemp)
      trap 'rm -f "$MANIFEST_TMP"' EXIT

      ${pkgs.age}/bin/age --decrypt \
        --identity "$USER_KEY" \
        --output "$MANIFEST_TMP" \
        "$MANIFEST_ENC"

      # Manifest format (YAML):
      #   secrets:
      #     <hashed_name>.age:
      #       name: <actual_name>
      #       type: env|file
      #       target: <optional target path for files>
      ${pkgs.yq-go}/bin/yq e \
        '.secrets | to_entries | .[] | [.key, .value.name, .value.type, .value.target // ""] | @tsv' \
        "$MANIFEST_TMP" | \
      while IFS=$'\t' read -r hashed_file actual_name secret_type target_path; do
        SOURCE_FILE="$SECRETS_DIR/$hashed_file"

        if [ ! -f "$SOURCE_FILE" ]; then
          echo "WARNING: Secret file not found: $SOURCE_FILE (for $actual_name)"
          continue
        fi

        if [ "$secret_type" = "env" ]; then
          TARGET_FILE="$TARGET_DIR/env/$actual_name"
        elif [ "$secret_type" = "file" ] && [ -n "$target_path" ]; then
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

        mkdir -p "$(dirname "$TARGET_FILE")"

        echo "${dryRunPrefix}Decrypting $actual_name -> $TARGET_FILE"
        ${pkgs.age}/bin/age --decrypt \
          --identity "$USER_KEY" \
          --output "$TARGET_FILE" \
          "$SOURCE_FILE"

        chown ${username}:${username} "$TARGET_FILE"
        chmod 0400 "$TARGET_FILE"
      done

      echo "${dryRunPrefix}User secrets for ${username} decrypted successfully"
    '';

  # Runs as root and chowns to the user, rather than running as the user.
  # Running as the user cannot work: the unit has to create directories under
  # /run/aegis/users, which root owns.
  mkUserSecretsService = username: {
    description = "Aegis: decrypt secrets for user ${username}${
        optionalString cfg.dryRun " (DRY-RUN)"
      }";
    wantedBy = [ "aegis-phase2.target" ];
    before = [ "aegis-phase2.target" ];
    after = [ "aegis-phase1.target" "aegis-user-key-${username}.service" ];
    requires = [ "aegis-phase1.target" "aegis-user-key-${username}.service" ];

    restartIfChanged = true;
    stopIfChanged = false;

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = userSecretsScript username;
    };
  };

  # Secret options submodule (manual configuration)
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
      default = false;
      description = ''
        Decrypt to a parallel tree under dryRunPath instead of the real
        targets, for migration testing.

        Ownership and permissions are logged rather than applied, and no
        production path is touched.

        Note this is NOT a safe default: services ordered after
        aegis-secrets.target still start, but find no secrets where they
        expect them. Enable it deliberately, verify, then turn it off.
      '';
    };

    dryRunPath = mkOption {
      type = types.str;
      default = "/run/aegis-dry-run";
      description = ''
        Root of the dry-run output tree. Targets are reproduced underneath it
        with their full path, so /etc/ssh/ssh_host_ed25519_key lands at
        ''${dryRunPath}/etc/ssh/ssh_host_ed25519_key.
      '';
    };

    secretsRepoPath = mkOption {
      type = types.nullOr types.path;
      description = ''
        Path to the aegis-secrets repository.

        The host's directory is found automatically as
          ''${secretsRepoPath}/deploy/hosts/''${networking.hostName}
        falling back to build/ for repositories that have not been migrated.

        This is the recommended way to configure aegis.

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
      type = types.nullOr types.path;
      description = ''
        Path to this specific host's secrets directory.

        Usually you should set secretsRepoPath instead and let this be
        computed as
          ''${secretsRepoPath}/deploy/hosts/''${networking.hostName}
        Only set this directly if you have a non-standard layout, or are
        supplying secrets from somewhere other than an aegis-secrets repo.
      ''';
      default = null;
      defaultText = literalExpression
        ''derived from secretsRepoPath, or null'';
      example = "/path/to/aegis-secrets/deploy/hosts/myhost";
    };

    resolvedSecretsPath = mkOption {
      type = types.nullOr types.str;
      description = "The host secrets directory actually in use (read-only).";
      default = if hostSecretsPath == null then null else toString hostSecretsPath;
      defaultText = literalExpression "secretsPath, or derived from secretsRepoPath";
      readOnly = true;
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
      default = "/state/master-key/key";
    };

    secrets = mkOption {
      type = types.attrsOf (types.submodule secretOpts);
      description = ''
        Extra secrets declared directly in Nix.

        Most secrets should come from the manifest instead; this is an escape
        hatch for anything it cannot express.
      '';
      default = { };
    };

    roles = mkOption {
      type = types.listOf types.str;
      description = ''
        Roles this host has (e.g., kdc, dns). Role keys are decrypted from
        roles/<role>.age inside the host secrets directory. Defaults to the
        roles list in secrets.toml.
      '';
      default = manifestRoles;
      defaultText = literalExpression "the roles list from secrets.toml";
      example = [ "kdc" "dns" ];
    };

    users = mkOption {
      type = types.listOf types.str;
      description = "Users whose secrets should be decrypted on this host.";
      default = [ ];
    };

    manageSshd = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Order sshd after aegis-phase1.target when the manifest supplies SSH
        host keys.

        Without this there is no ordering edge between them: sshd is wantedBy
        multi-user.target and so are the decryption units, so sshd can start
        before its host keys exist.
      '';
    };

    verbose = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Print the list of secrets configured for this host at evaluation time.
      '';
    };

    # =========================================================================
    # Manifest data (read-only), for reference from other NixOS config
    # =========================================================================

    manifest = {
      loaded = mkOption {
        type = types.bool;
        description = "Whether a secrets.toml manifest was found and loaded.";
        default = manifestExists;
        defaultText = literalExpression "true if secrets.toml exists";
        readOnly = true;
      };

      path = mkOption {
        type = types.nullOr types.str;
        description = "Path the manifest was read from, if any.";
        default = if manifestPath == null then null else toString manifestPath;
        defaultText = literalExpression "''${secretsPath}/secrets.toml";
        readOnly = true;
      };

      sshHostKeys = mkOption {
        type = types.listOf (types.attrsOf types.anything);
        description = ''
          SSH host keys from the manifest, with resolved target paths.
          Useful for referring to a key path elsewhere in your config.
        '';
        default = map (entry: {
          inherit (entry) target pubTarget user group mode;
          type = entry.keyType;
        }) sshEntries;
        readOnly = true;
      };

      targets = mkOption {
        type = types.attrsOf types.str;
        description = ''
          Map of secret name to the path it is decrypted to. Use this instead
          of hardcoding paths in service configuration.
        '';
        default = listToAttrs
          (map (entry: nameValuePair entry.name entry.target) allEntries);
        readOnly = true;
      };

      roles = mkOption {
        type = types.listOf types.str;
        description = "Roles declared in secrets.toml for this host.";
        default = manifestRoles;
        readOnly = true;
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = manifestExists || cfg.secrets != { };
        message = ''
          Aegis is enabled for ${hostname} but there are no secrets to manage.

          ${
            if manifestPath == null then
              "Neither secretsRepoPath nor secretsPath is set, so there is nowhere to read a manifest from."
            else
              "No manifest was found at ${manifestPath}."
          }

          Either the host has not been built yet (run 'aegis build' in your
          aegis-secrets repo), or secretsRepoPath points somewhere unexpected.
        '';
      }
      {
        assertion = !(cfg.users != [ ] && !manifestExists);
        message = ''
          aegis.secrets.users is set for ${hostname} but no manifest was found,
          so there are no user deployment keys to decrypt.
        '';
      }
    ];

    warnings = optionals cfg.dryRun [''
      ╔═══════════════════════════════════════════════════════════════════╗
      ║                    AEGIS DRY-RUN MODE ENABLED                     ║
      ╠═══════════════════════════════════════════════════════════════════╣
      ║  Secrets are being decrypted to ${stringPadRight 34 cfg.dryRunPath}║
      ║  for testing purposes only. Production paths are NOT affected.    ║
      ║                                                                   ║
      ║  Services depending on aegis-secrets.target WILL start, and will  ║
      ║  not find their secrets. Do not leave this enabled.               ║
      ║                                                                   ║
      ║  To deploy secrets for real, set:                                 ║
      ║    aegis.secrets.dryRun = false;                                  ║
      ╚═══════════════════════════════════════════════════════════════════╝
    ''] ++ optionals (!manifestExists && cfg.secrets != { }) [''
      Aegis [${hostname}]: no manifest found; using only the ${
        toString (length (attrNames cfg.secrets))
      } secret(s) declared in Nix.
    ''] ++ optionals cfg.verbose [''
      Aegis [${hostname}]: ${
        toString (length allEntries)
      } secret(s) configured for this host:
      ${
        concatMapStringsSep "\n"
        (entry: "  - ${entry.name} -> ${entry.target}") allEntries
      }
    ''];

    systemd.tmpfiles.rules = [
      "d /run/aegis 0755 root root - -"
      "d /run/aegis/users 0755 root root - -"
      "d /run/aegis/roles 0755 root root - -"
    ] ++ optionals cfg.dryRun [ "d ${cfg.dryRunPath} 0755 root root - -" ];

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

    systemd.services = listToAttrs (map (entry:
      nameValuePair "aegis-${entry.name}" (mkSecretService entry)) allEntries)
      // listToAttrs (map (username:
        nameValuePair "aegis-user-secrets-${username}"
        (mkUserSecretsService username)) cfg.users)
      # sshd must not start before the keys it identifies itself with exist.
      // optionalAttrs (cfg.manageSshd && sshEntries != [ ] && !cfg.dryRun) {
        sshd = {
          after = [ "aegis-phase1.target" ];
          requires = [ "aegis-phase1.target" ];
        };
      };

    users.groups.aegis-secrets = { };
  };
}
