{ config, lib, ... }:

# Exports secrets that `aegis.secrets` decrypted for this user as session
# variables.
#
# This module is the last link in the user-secrets chain, and the chain is
# currently broken upstream of it: nothing decrypts anything into
# `secretsBasePath`, so every variable here resolves to nothing.  See
# ../TODO.md ("User secrets do not work end to end") before relying on it.
#
# What it expects to find, once that is fixed:
#
#   /run/aegis/users/<username>/env/<NAME>    one variable per file
#   /run/aegis/users/<username>/files/<name>  file secrets
#
# written by the phase-2 unit in ../modules/secrets.nix.

with lib;

let cfg = config.aegis.userSecrets;

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

    sessionVariablesFromSecrets = mkOption {
      type = types.listOf types.str;
      description = ''
        Secret names to export as session variables. Each is read from
        <literal>secretsBasePath/env/&lt;name&gt;</literal> at login.

        A name that has no file is skipped rather than exported empty, so a
        host that is not entitled to a secret simply does not set it.
      '';
      default = [ ];
      example = [ "GITHUB_TOKEN" "OPENAI_API_KEY" ];
    };
  };

  config = mkIf cfg.enable {
    # Read at login by the shell, not at evaluation time: the plaintext must
    # never reach the Nix store, and it does not exist when the config is
    # built.
    home.sessionVariablesExtra =
      mkIf (cfg.sessionVariablesFromSecrets != [ ]) ''
        # Aegis user secrets
        ${concatMapStringsSep "\n" (name: ''
          if [ -r "${cfg.secretsBasePath}/env/${name}" ]; then
            export ${name}="$(cat "${cfg.secretsBasePath}/env/${name}")"
          fi
        '') cfg.sessionVariablesFromSecrets}
      '';
  };
}
