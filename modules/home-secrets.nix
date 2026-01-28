{ config, lib, pkgs, ... }:

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

    envVars = mkOption {
      type = types.attrsOf types.str;
      description = ''
        Environment variables from secrets.
        Keys are variable names, values are paths to decrypted secret files.
      '';
      default = { };
      example = {
        GITHUB_TOKEN = "/run/aegis/users/niten/env/GITHUB_TOKEN";
        OPENAI_API_KEY = "/run/aegis/users/niten/env/OPENAI_API_KEY";
      };
    };

    sessionVariablesFromSecrets = mkOption {
      type = types.listOf types.str;
      description = ''
        List of secret names to export as session variables.
        These will be read from secretsBasePath/env/<name> at login time.
      '';
      default = [ ];
      example = [ "GITHUB_TOKEN" "OPENAI_API_KEY" ];
    };
  };

  config = mkIf cfg.enable {
    # Source the secrets into the session
    # This creates a script that reads secret files and exports them
    home.sessionVariablesExtra =
      mkIf (cfg.sessionVariablesFromSecrets != [ ]) ''
        # Aegis user secrets
        ${concatMapStringsSep "\n" (name: ''
          if [ -f "${cfg.secretsBasePath}/env/${name}" ]; then
            export ${name}="$(cat "${cfg.secretsBasePath}/env/${name}")"
          fi
        '') cfg.sessionVariablesFromSecrets}
      '';

    # For explicitly mapped env vars
    home.sessionVariables =
      mapAttrs (name: path: "$(cat ${path} 2>/dev/null || echo '')")
      cfg.envVars;
  };
}
