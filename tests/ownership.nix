# Ownership validation: a secret owned by a user or group the host does not
# declare fails evaluation, rather than failing `chown` at boot after the
# plaintext has already been written.
#
# This is an evaluation test, not a VM test: the behaviour under test is that
# the configuration does not evaluate, which no VM can observe.  It reads
# `config.assertions` directly rather than forcing `system.build.toplevel`, so
# it neither builds a system nor has to care about the unrelated assertions
# (root filesystem, boot loader) that a skeleton host trips.
{ pkgs, nixpkgs, system }:

let
  inherit (nixpkgs) lib;

  missingUser = "aegis-no-such-user";
  missingGroup = "aegis-no-such-group";

  # A secret owned by whoever the case under test says.  `source` is never
  # read: nothing here is built, let alone decrypted.
  base = { user, group, ... }@args: {
    imports = [ ../modules/secrets.nix ];

    # Enough of a host to evaluate. The platform comes from eval-config's
    # `system` argument, so it is deliberately not set here as well.
    boot.loader.grub.enable = false;
    fileSystems."/" = {
      device = "/dev/null";
      fsType = "ext4";
    };
    system.stateVersion = lib.trivial.release;

    aegis.secrets = {
      enable = true;
      dryRun = args.dryRun or false;
      masterKeyPath = "/var/lib/aegis/master-key";
      unmanagedUsers = args.unmanagedUsers or [ ];
      unmanagedGroups = args.unmanagedGroups or [ ];

      secrets.owned = {
        source = ./ownership.nix;
        target = "/run/aegis/owned";
        inherit user group;
      };
    };
  };

  evalHost = module:
    (import "${nixpkgs}/nixos/lib/eval-config.nix" {
      inherit system;
      modules = [ module ];
    }).config;

  failedMessages = module:
    map (a: a.message) (lib.filter (a: !a.assertion) (evalHost module).assertions);

  warningMessages = module: (evalHost module).warnings;

  mentions = needle: msgs: lib.any (m: lib.hasInfix needle m) msgs;

  cases = {
    # The forge case: the manifest names a service user, but the service that
    # would declare it is not enabled on this host.
    missing-user-fails = let
      msgs = failedMessages (base {
        user = missingUser;
        group = "root";
      });
    in {
      ok = mentions missingUser msgs;
      why = "a secret owned by an undeclared user must fail evaluation";
    };

    missing-group-fails = let
      msgs = failedMessages (base {
        user = "root";
        group = missingGroup;
      });
    in {
      ok = mentions missingGroup msgs;
      why = "a secret owned by an undeclared group must fail evaluation";
    };

    # The fix: declare the user, as the owning service module would.
    declared-user-passes = let
      msgs = failedMessages {
        imports = [
          (base {
            user = missingUser;
            group = missingUser;
          })
        ];

        users.users.${missingUser} = {
          isSystemUser = true;
          group = missingUser;
        };
        users.groups.${missingUser} = { };
      };
    in {
      ok = !(mentions missingUser msgs);
      why = "a declared user and group must satisfy the assertion";
    };

    # The escape hatch, for an account Nix cannot see.
    unmanaged-user-passes = let
      msgs = failedMessages (base {
        user = missingUser;
        group = missingGroup;
        unmanagedUsers = [ missingUser ];
        unmanagedGroups = [ missingGroup ];
      });
    in {
      ok = !(mentions missingUser msgs) && !(mentions missingGroup msgs);
      why = "unmanagedUsers/unmanagedGroups must suppress the assertion";
    };

    # Dry-run never chowns, so there is nothing to fail yet -- but the host is
    # about to be flipped, so it has to be told.
    dry-run-warns-instead = let
      module = base {
        user = missingUser;
        group = "root";
        dryRun = true;
      };
    in {
      ok = !(mentions missingUser (failedMessages module))
        && mentions missingUser (warningMessages module);
      why = "dry-run must warn about a missing owner, not fail the build";
    };

    # chown takes numeric ids too, and a manifest may use them.
    numeric-id-passes = let
      msgs = failedMessages (base {
        user = "1234";
        group = "1234";
      });
    in {
      ok = !(mentions "\"1234\"" msgs);
      why = "a numeric uid/gid must not be treated as a missing account";
    };
  };

  failed = lib.filterAttrs (_: case: !case.ok) cases;

in if failed != { } then
  throw ''
    aegis ownership validation test failed:
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: case: "  ${name}: ${case.why}") failed)}
  ''
else
  pkgs.runCommand "aegis-ownership-test" { } ''
    echo "ownership validation: ${
      toString (lib.length (lib.attrNames cases))
    } cases passed"
    touch $out
  ''
