{ config, lib, pkgs, ... }:

# The user-facing half of Aegis user secrets.
#
# `aegis.secrets.users` on the host decrypts a user's secrets to
#
#   /run/aegis/users/<username>/env/<NAME>     one variable per file
#   /run/aegis/users/<username>/files/<name>   file secrets
#
# owned by that user, mode 0400, on tmpfs.  This module turns those into
# something a session can actually use: environment variables at login, and
# files at the paths the user wants them.
#
# Nothing here reads a secret at evaluation time.  Everything is resolved at
# login or by a systemd user unit, because the plaintext must not reach the Nix
# store and does not exist when the configuration is built.

with lib;

let
  cfg = config.aegis.userSecrets;

  envDir = "${cfg.secretsBasePath}/env";
  filesDir = "${cfg.secretsBasePath}/files";

  fileOpts = { ... }: {
    options = {
      target = mkOption {
        type = types.str;
        description = ''
          Where to place this secret, relative to the home directory.
        '';
        example = ".config/rclone/rclone.conf";
      };

      method = mkOption {
        type = types.enum [ "symlink" "copy" ];
        default = "symlink";
        description = ''
          <literal>symlink</literal> points at the file on tmpfs: no plaintext
          is written to disk and it disappears on reboot with everything else
          under <filename>/run</filename>. Prefer it.

          <literal>copy</literal> writes the plaintext into the home directory,
          where it survives a reboot and has to be cleaned up. Only for
          programs that reject a symlink -- ssh with <literal>StrictModes</literal>
          being the usual one.
        '';
      };

      mode = mkOption {
        type = types.str;
        default = "0400";
        description = ''
          Permissions for the placed file. Only meaningful with
          <literal>method = "copy"</literal>; a symlink takes the mode of what
          it points at.
        '';
      };
    };
  };

  # Rejected outright rather than exported. A secret named PATH or LD_PRELOAD
  # is not a credential, it is a way to change what the next command in the
  # login shell is. The user's own secrets repo is not a trusted input here:
  # `aegis build user-secrets` re-encrypts whatever names it finds, so the
  # first time anyone notices would be a shell behaving strangely.
  refusedNames = [
    "BASH_ENV"
    "CDPATH"
    "ENV"
    "GLOBIGNORE"
    "HOME"
    "IFS"
    "LD_AUDIT"
    "LD_LIBRARY_PATH"
    "LD_PRELOAD"
    "NODE_OPTIONS"
    "PATH"
    "PERL5LIB"
    "PERL5OPT"
    "PROMPT_COMMAND"
    "PS4"
    "PYTHONPATH"
    "PYTHONSTARTUP"
    "SHELL"
    "SHELLOPTS"
    "ZDOTDIR"
  ];

  # POSIX sh: this is sourced by hm-session-vars.sh, which is read by ~/.profile
  # and by shells that are not bash.
  exportAllSnippet = ''
    if [ -d "${envDir}" ]; then
      for _aegis_file in "${envDir}"/*; do
        [ -r "$_aegis_file" ] || continue
        _aegis_name="''${_aegis_file##*/}"

        # Anything that is not a plausible variable name is a corrupt or
        # hostile manifest entry, not a secret worth exporting.
        case "$_aegis_name" in
          "" | [0-9]* | *[!A-Za-z0-9_]*) continue ;;
        esac

        case "$_aegis_name" in
          ${concatStringsSep " | " refusedNames})
            echo "aegis: refusing to export $_aegis_name from user secrets" >&2
            continue
            ;;
        esac

        export "$_aegis_name=$(cat "$_aegis_file")"
      done
      unset _aegis_file _aegis_name
    fi
  '';

  explicitSnippet = concatMapStringsSep "\n" (name: ''
    if [ -r "${envDir}/${name}" ]; then
      export ${name}="$(cat "${envDir}/${name}")"
    fi
  '') cfg.sessionVariablesFromSecrets;

  placeFilesScript = pkgs.writeShellScript "aegis-user-files" ''
    set -euo pipefail
    PATH=${makeBinPath [ pkgs.coreutils ]}:$PATH

    if [ ! -d "${filesDir}" ]; then
      echo "aegis: ${filesDir} does not exist; nothing to place."
      echo "aegis: is this user listed in aegis.secrets.users on this host?"
      exit 0
    fi

    ${concatStringsSep "\n" (mapAttrsToList (name: file: ''
      source="${filesDir}/${name}"
      target="$HOME/${file.target}"

      if [ ! -r "$source" ]; then
        echo "aegis: no secret named ${name} at $source, skipping ${file.target}"
      else
        mkdir -p "$(dirname "$target")"
        # Replace whatever is there. A stale symlink into a previous boot's
        # /run is the common case, and it is indistinguishable from a live one
        # without following it.
        rm -f "$target"
        ${
          if file.method == "copy" then ''
            cp "$source" "$target"
            chmod ${file.mode} "$target"
          '' else ''
            ln -s "$source" "$target"
          ''
        }
        echo "aegis: ${name} -> ~/${file.target}"
      fi
    '') cfg.files)}
  '';

in {
  options.aegis.userSecrets = {
    enable = mkEnableOption "Aegis user secrets";

    username = mkOption {
      type = types.str;
      description = "Username for secrets lookup.";
      default = config.home.username;
    };

    secretsBasePath = mkOption {
      type = types.str;
      description = "Base path where user secrets are decrypted.";
      default = "/run/aegis/users/${cfg.username}";
    };

    exportAll = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Export every file under
        <literal>secretsBasePath/env/</literal> as a session variable, named
        after the file.

        This is the default because the alternative is declaring each name in
        two places -- here and in the user's secrets repo -- where the copy in
        the Nix configuration serves no purpose except to be forgotten. A
        secret the host is not entitled to simply is not there, so nothing is
        exported for it.

        Names that are not valid shell identifiers are skipped, and a short
        list of variables that change how the shell or the dynamic linker
        behave (PATH, LD_PRELOAD, IFS, ...) is refused with a message.
      '';
    };

    sessionVariablesFromSecrets = mkOption {
      type = types.listOf types.str;
      description = ''
        Secret names to export explicitly. Redundant when
        <option>exportAll</option> is on, which is the default; set
        <option>exportAll</option> to false and list names here to export only
        a known set.
      '';
      default = [ ];
      example = [ "GITHUB_TOKEN" "OPENAI_API_KEY" ];
    };

    files = mkOption {
      type = types.attrsOf (types.submodule fileOpts);
      default = { };
      description = ''
        File secrets to place in the home directory. The attribute name is the
        secret's name as given to <literal>aegis-user add-file</literal>.

        Unlike environment variables these are declared rather than
        discovered: only the user knows where a given file belongs, and that
        is configuration, not a secret.
      '';
      example = literalExpression ''
        {
          aws-creds.target = ".aws/credentials";
          ssh-work = {
            target = ".ssh/id_work";
            method = "copy";   # ssh rejects a symlinked key under StrictModes
            mode = "0600";
          };
        }
      '';
    };
  };

  config = mkIf cfg.enable {
    home.sessionVariablesExtra = mkIf
      (cfg.exportAll || cfg.sessionVariablesFromSecrets != [ ]) ''
        # Aegis user secrets
        ${optionalString cfg.exportAll exportAllSnippet}
        ${explicitSnippet}
      '';

    # A user unit rather than an activation script: the files live on tmpfs and
    # have to be re-placed after every reboot, which an activation script only
    # does if the configuration happens to change. Ordered after
    # default.target's usual prerequisites, by which point the system's phase-2
    # units have long since run -- they complete before multi-user.target.
    systemd.user.services.aegis-user-files = mkIf (cfg.files != { }) {
      Unit.Description = "Place Aegis user file secrets";
      Service = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${placeFilesScript}";
      };
      Install.WantedBy = [ "default.target" ];
    };
  };
}
