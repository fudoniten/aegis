{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.aegis.userSecrets;

  # Where the host's aegis-user-secrets-<user> unit decrypts each kind of
  # secret (see modules/secrets.nix).
  filePath = name: "${cfg.secretsBasePath}/files/${name}";
  envPath = name: "${cfg.secretsBasePath}/env/${name}";

  # A home.file / xdg.configFile entry that is a symlink to the decrypted
  # file.  Out of store: the plaintext only exists under /run on the host,
  # and must never be copied into the Nix store.
  link = name: {
    source = config.lib.file.mkOutOfStoreSymlink (filePath name);
  };

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

    files = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = {
        ".aws/credentials" = "aws-creds";
        ".config/rclone/rclone.conf" = "rclone";
      };
      description = ''
        Files to link into your home directory, as
        `"<path relative to $HOME>" = "<secret name>"`.  The secret name is
        the one you gave `aegis-user add-file`.  Each becomes a symlink to
        the decrypted copy under secretsBasePath/files, so the plaintext
        never enters the Nix store.

        For a location this does not cover (`xdg.configFile`, an option that
        wants a path), use the `link` and `path` helpers instead.
      '';
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

    # Helpers, for referring to a secret from elsewhere in your config.
    # Read-only: they are functions of the secret name, not settings.

    link = mkOption {
      type = types.functionTo types.attrs;
      readOnly = true;
      default = link;
      defaultText = literalExpression ''name: { source = <symlink to secretsBasePath/files/name>; }'';
      example = literalExpression ''
        {
          home.file.".aws/credentials" = config.aegis.userSecrets.link "aws-creds";
          xdg.configFile."rclone/rclone.conf" = config.aegis.userSecrets.link "rclone";
        }
      '';
      description = ''
        `link "<secret>"` is a complete `home.file` (or `xdg.configFile`)
        entry: a symlink to the decrypted file secret.
      '';
    };

    path = mkOption {
      type = types.functionTo types.str;
      readOnly = true;
      default = filePath;
      defaultText = literalExpression ''name: "''${secretsBasePath}/files/''${name}"'';
      example = literalExpression ''
        programs.foo.passwordFile = config.aegis.userSecrets.path "foo-password";
      '';
      description = ''
        `path "<secret>"` is the absolute path of a decrypted file secret, for
        options that take a path to read at runtime.
      '';
    };

    envPath = mkOption {
      type = types.functionTo types.str;
      readOnly = true;
      default = envPath;
      defaultText = literalExpression ''name: "''${secretsBasePath}/env/''${name}"'';
      description = ''
        `envPath "<NAME>"` is the absolute path of a decrypted env secret
        (the file holding its value).
      '';
    };
  };

  config = mkIf cfg.enable {
    home.file = mapAttrs (_: link) cfg.files;

    # Source the secrets into the session
    # This creates a script that reads secret files and exports them
    home.sessionVariablesExtra =
      mkIf (cfg.sessionVariablesFromSecrets != [ ]) ''
        # Aegis user secrets
        ${concatMapStringsSep "\n" (name: ''
          if [ -f "${envPath name}" ]; then
            export ${name}="$(cat "${envPath name}")"
          fi
        '') cfg.sessionVariablesFromSecrets}
      '';

    # For explicitly mapped env vars
    home.sessionVariables =
      mapAttrs (name: path: "$(cat ${path} 2>/dev/null || echo '')")
      cfg.envVars;
  };
}
