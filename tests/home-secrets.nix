# The Home Manager module, evaluated against a stand-in for the few Home
# Manager options it touches -- so this needs no home-manager input, and checks
# what the module emits rather than what Home Manager does with it.
#
# The stand-in mkOutOfStoreSymlink returns its argument, so a link's `source`
# is the path the real one would point at.  Evaluation-only.
{ pkgs, nixpkgs }:

let
  inherit (nixpkgs) lib;

  hmStub = { lib, ... }: {
    options = {
      home.username = lib.mkOption { type = lib.types.str; };
      home.file = lib.mkOption { type = lib.types.attrsOf lib.types.attrs; default = { }; };
      xdg.configFile = lib.mkOption { type = lib.types.attrsOf lib.types.attrs; default = { }; };
      home.sessionVariables = lib.mkOption { type = lib.types.attrsOf lib.types.str; default = { }; };
      home.sessionVariablesExtra = lib.mkOption { type = lib.types.lines; default = ""; };
      lib = lib.mkOption { type = lib.types.attrsOf lib.types.attrs; default = { }; };
    };
    config.lib.file.mkOutOfStoreSymlink = path: path;
  };

  eval = lib.evalModules {
    specialArgs = { inherit pkgs; };
    modules = [
      hmStub
      ../modules/home-secrets.nix
      ({ config, ... }: {
        home.username = "alice";
        aegis.userSecrets = {
          enable = true;
          files.".aws/credentials" = "aws-creds";
          sessionVariablesFromSecrets = [ "GITHUB_TOKEN" ];
        };
        xdg.configFile."rclone/rclone.conf" = config.aegis.userSecrets.link "rclone";
        home.sessionVariables.FOO_FILE = config.aegis.userSecrets.path "foo";
      })
    ];
  };
  c = eval.config;

  checks = {
    "files links into home" =
      c.home.file.".aws/credentials".source == "/run/aegis/users/alice/files/aws-creds";
    "link is a whole home.file entry" =
      c.xdg.configFile."rclone/rclone.conf" == { source = "/run/aegis/users/alice/files/rclone"; };
    "path is the decrypted file" =
      c.home.sessionVariables.FOO_FILE == "/run/aegis/users/alice/files/foo";
    "envPath is the decrypted value" =
      c.aegis.userSecrets.envPath "GITHUB_TOKEN" == "/run/aegis/users/alice/env/GITHUB_TOKEN";
    "session variables read env/" =
      lib.hasInfix ''"/run/aegis/users/alice/env/GITHUB_TOKEN"'' c.home.sessionVariablesExtra;
  };
  failed = lib.attrNames (lib.filterAttrs (_: ok: !ok) checks);

in if failed == [ ] then
  pkgs.runCommand "aegis-home-secrets-test" { } "touch $out"
else
  throw "home-secrets: failed: ${lib.concatStringsSep ", " failed}"
