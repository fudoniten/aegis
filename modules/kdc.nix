{ config, lib, pkgs, ... }:

# Aegis KDC: rebuild a Heimdal KDC database from the principal bundle in
# aegis-secrets.
#
# `aegis build keytabs` / `aegis realm export` produce, per realm:
#
#   deploy/kdc/<REALM>-principals.age   every principal, as decrypted dump lines
#   deploy/kdc/<REALM>-realm-key.age    the realm master key
#
# both encrypted for the realm's KDC role. A host in that role decrypts the
# role key in phase 1 and these two in phase 2, then merges the bundle into the
# live database.
#
# The merge is deliberately not a replace: principals that exist only in the
# live database -- users created on the KDC with kadmin -- are preserved, while
# the repo stays authoritative for host and service principals.

with lib;

let
  cfg = config.aegis.kdc;
  secretsCfg = config.aegis.secrets;

  roleKeyPath = "/run/aegis/roles/${cfg.role}";

  principalsSource = if cfg.principalsSource != null then
    cfg.principalsSource
  else
    "${cfg.kdcSecretsPath}/${cfg.realm}-principals.age";

  realmKeySource = if cfg.realmKeySource != null then
    cfg.realmKeySource
  else
    "${cfg.kdcSecretsPath}/${cfg.realm}-realm-key.age";

  # `aegis build keytabs` writes one of these per realm for each entry in
  # `_KDC_SERVICE_KEYTABS` it found a principal for -- kadmind and kpasswdd
  # always, hprop only for a realm doing replication. Distinct from the host
  # keytabs `aegis.secrets` places: these authenticate the KDC's own daemons,
  # not a realm member, so they are decrypted here with the role key rather
  # than a host key.
  serviceKeytabSource = name: "${cfg.kdcSecretsPath}/${cfg.realm}-${name}.keytab.age";

  mergeScript = pkgs.writeShellScript "aegis-kdc-merge-${cfg.realm}" ''
    set -euo pipefail

    ROLE_KEY="${roleKeyPath}"
    STATE_DIR="${cfg.stateDir}"
    DB="${cfg.databasePath}"
    REALM_KEY="${cfg.realmKeyPath}"

    if [ ! -r "$ROLE_KEY" ]; then
      echo "ERROR: role key not readable: $ROLE_KEY" >&2
      echo "Is this host a member of role '${cfg.role}'?" >&2
      exit 1
    fi

    install -d -m 0700 -o ${cfg.user} -g ${cfg.group} "$STATE_DIR"

    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK"' EXIT

    echo "Decrypting realm master key..."
    ${pkgs.age}/bin/age --decrypt \
      --identity "$ROLE_KEY" \
      --output "$WORK/realm.key" \
      "${realmKeySource}"

    echo "Decrypting principal bundle..."
    ${pkgs.age}/bin/age --decrypt \
      --identity "$ROLE_KEY" \
      --output "$WORK/principals" \
      "${principalsSource}"

    install -m 0600 -o ${cfg.user} -g ${cfg.group} "$WORK/realm.key" "$REALM_KEY"

    ${concatStringsSep "\n" (mapAttrsToList (name: target: ''
      echo "Decrypting ${name} service keytab..."
      install -d -m 0700 -o ${cfg.user} -g ${cfg.group} "$(dirname ${target})"
      ${pkgs.age}/bin/age --decrypt \
        --identity "$ROLE_KEY" \
        --output "${target}" \
        "${serviceKeytabSource name}"
      chown ${cfg.user}:${cfg.group} "${target}"
      chmod 0600 "${target}"
    '') cfg.serviceKeytabs)}

    # fudo-nix-lib's KDC module pre-creates the database with a systemd-tmpfiles
    # rule of type `f`, so on a KDC's first boot $DB is a zero-byte file rather
    # than absent. kdc-merge-principals.rb decides whether to dump an
    # existing database on `File::exist?` alone, so that placeholder sends it
    # down the "merge into existing" path, where kadmin fails with
    #
    #   Failed to prepare stmt SELECT number FROM Version: no such table: Version
    #
    # and takes this unit -- and so the whole KDC rollout -- with it, on exactly
    # the boot where there is nothing to preserve.
    #
    # Only a zero-length file is removed. The merge script builds the new
    # database in a temporary directory and moves it into place either way; the
    # existing one is read solely to carry forward principals created locally
    # with kadmin. A non-empty database that cannot be dumped is a real failure
    # and must stay loud rather than be silently discarded.
    if [ -e "$DB" ] && [ ! -s "$DB" ]; then
      echo "Removing empty database placeholder: $DB"
      rm -f "$DB"
    fi

    echo "Merging principals into $DB..."
    # kdc-merge-principals.rb keeps any principal that exists in the live
    # database but not in the incoming bundle, so locally-created user
    # principals survive a rebuild.
    ${pkgs.ruby}/bin/ruby ${cfg.mergeScript} \
      --realm "${cfg.realm}" \
      --database "$DB" \
      --principals "$WORK/principals" \
      --key "$REALM_KEY" \
      --verbose

    chown ${cfg.user}:${cfg.group} "$DB"
    chmod 0600 "$DB"

    echo "KDC database for ${cfg.realm} is up to date."
  '';

in {
  options.aegis.kdc = {
    enable = mkEnableOption "Aegis-managed Heimdal KDC database";

    realm = mkOption {
      type = types.str;
      description = "Kerberos realm this KDC serves.";
      example = "SEA.FUDO.ORG";
    };

    role = mkOption {
      type = types.str;
      default = "kdc";
      description = ''
        Role whose key decrypts the principal bundle. Must match the realm's
        kdc_role in aegis-secrets, and this host must be a member.
      '';
    };

    kdcSecretsPath = mkOption {
      type = types.str;
      description = ''
        Directory holding the per-realm KDC bundles, normally
        ''${aegis-secrets}/deploy/kdc.
      '';
      default = let repo = secretsCfg.secretsRepoPath;
      in if repo != null then
        (if builtins.pathExists "${repo}/deploy/kdc" then
          "${repo}/deploy/kdc"
        else
          "${repo}/build/kdc")
      else
        "";
      defaultText = literalExpression ''"''${secretsRepoPath}/deploy/kdc"'';
    };

    principalsSource = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Explicit path to the encrypted principal bundle. Derived from
        kdcSecretsPath and realm when null.
      '';
    };

    realmKeySource = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Explicit path to the encrypted realm master key. Derived from
        kdcSecretsPath and realm when null.
      '';
    };

    databasePath = mkOption {
      type = types.str;
      default = "/var/lib/heimdal/heimdal.db";
      description = "Path to the Heimdal KDC database.";
    };

    realmKeyPath = mkOption {
      type = types.str;
      default = "/var/lib/heimdal/m-key";
      description = "Where the decrypted realm master key is installed.";
    };

    stateDir = mkOption {
      type = types.str;
      default = "/var/lib/heimdal";
      description = "Directory holding the KDC database and master key.";
    };

    user = mkOption {
      type = types.str;
      default = "root";
      description = "Owner of the KDC database and master key.";
    };

    group = mkOption {
      type = types.str;
      default = "root";
      description = "Group of the KDC database and master key.";
    };

    mergeScript = mkOption {
      type = types.path;
      description = ''
        Path to kdc-merge-principals.rb. Point this at the copy shipped by
        aegis-tools-system.
      '';
      example =
        literalExpression ''"''${inputs.aegis-tools-system}/scripts/kdc-merge-principals.rb"'';
    };

    restartServices = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Services to restart after the database is rebuilt, e.g. [ "kdc" ].
      '';
      example = [ "kdc" "kadmind" ];
    };

    serviceKeytabs = mkOption {
      type = types.attrsOf types.str;
      default = { };
      description = ''
        Map of KDC service keytab name (as `aegis build keytabs` names them --
        "kadmind", "kpasswdd", "hprop") to the path this host should decrypt
        it to. Each name must have a corresponding
        `deploy/kdc/<REALM>-<name>.keytab.age` in the secrets repo, or the
        merge script fails outright rather than silently starting a KDC whose
        admin/password daemons cannot authenticate.

        These are separate from the per-host keytabs `aegis.secrets` places:
        they authenticate the KDC's own daemons, encrypted to the KDC role
        rather than any one host's key.
      '';
      example = literalExpression ''
        {
          kadmind = "/var/lib/heimdal/kadmind.keytab";
          kpasswdd = "/var/lib/heimdal/kpasswdd.keytab";
        }
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = config.aegis.secrets.enable;
        message = "aegis.kdc requires aegis.secrets to be enabled.";
      }
      {
        assertion = elem cfg.role config.aegis.secrets.roles;
        message = ''
          aegis.kdc.role is "${cfg.role}" but this host does not have that role.

          Roles come from secrets.toml; add the host with:
            aegis role add-host ${cfg.role} ${config.networking.hostName}
          and rebuild. Without the role key the principal bundle cannot be
          decrypted.
        '';
      }
      {
        assertion = cfg.kdcSecretsPath != "";
        message = ''
          aegis.kdc.kdcSecretsPath could not be derived: set
          aegis.secrets.secretsRepoPath, or set kdcSecretsPath explicitly.
        '';
      }
      {
        assertion = !config.aegis.secrets.dryRun;
        message = ''
          aegis.kdc cannot run in dry-run mode: it would write a real KDC
          database from secrets decrypted to the dry-run tree.
        '';
      }
    ];

    systemd.services = {
      "aegis-kdc-${cfg.realm}" = {
        description = "Aegis: rebuild KDC database for ${cfg.realm}";
        wantedBy = [ "aegis-phase2.target" ];
        before = [ "aegis-phase2.target" ];
        after = [ "aegis-phase1.target" "aegis-role-${cfg.role}.service" ];
        requires = [ "aegis-phase1.target" "aegis-role-${cfg.role}.service" ];

        restartIfChanged = true;
        stopIfChanged = false;

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = mergeScript;
        };
      };
    } // listToAttrs (map (name:
      nameValuePair name {
        after = [ "aegis-kdc-${cfg.realm}.service" ];
        wants = [ "aegis-kdc-${cfg.realm}.service" ];
      }) cfg.restartServices);
  };
}
