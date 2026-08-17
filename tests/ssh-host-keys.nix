# `[[ssh-host-keys]]` validation: the list is what sshd presents as this
# host's identity, so an entry that cannot be one has to be caught here.
#
# Two shapes, both of which reached production manifests:
#
#   - a `type` ssh-keygen does not have (`deploy_ed25519`, `initrd_ed25519`),
#     from sweeping the legacy tree's deploy/ and initrd/ keypairs into the
#     same list as host/
#   - the same `type` on more than one entry, which collapses their decrypt
#     units into one and leaves the rest of the targets unwritten
#
# An evaluation test rather than a VM test, for the same reason as
# ownership.nix: the behaviour under test is that the configuration does not
# evaluate. It reads `config.assertions` directly, so nothing is built and the
# unrelated assertions a skeleton host trips do not matter.
{ pkgs, nixpkgs, system }:

let
  inherit (nixpkgs) lib;

  sshEntry = { source, target, type ? null }: ''
    [[ssh-host-keys]]
    source = "${source}"
    target = "${target}"
    target_dir = "/run/aegis/ssh"
    user = "root"
    group = "root"
    mode = "0600"
    ${lib.optionalString (type != null) ''type = "${type}"''}
  '';

  # Only the manifest is needed: nothing here is built, let alone decrypted,
  # so the .age files it names never have to exist.
  manifestDir = entries:
    pkgs.writeTextDir "secrets.toml"
    (lib.concatMapStringsSep "\n" sshEntry entries);

  hostKey = {
    source = "ssh/ssh_host_ed25519_key.age";
    target = "ssh_host_ed25519_key";
    type = "ed25519";
  };

  ecdsaKey = {
    source = "ssh/ssh_host_ecdsa_key.age";
    target = "ssh_host_ecdsa_key";
    type = "ecdsa";
  };

  deployKey = {
    source = "ssh/deploy_ed25519_key.age";
    target = "deploy_ed25519_key";
    type = "deploy_ed25519";
  };

  base = { entries, dryRun ? false }: {
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
      inherit dryRun;
      masterKeyPath = "/var/lib/aegis/master-key";
      secretsPath = manifestDir entries;
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
    # nomenclator-0, locum and procul: the deploy and initrd keypairs were
    # imported alongside the real host keys.
    non-sshd-type-fails = let
      msgs = failedMessages (base { entries = [ hostKey ecdsaKey deployKey ]; });
    in {
      ok = mentions "deploy_ed25519" msgs;
      why = "a type ssh-keygen does not have must fail evaluation";
    };

    # forge's shape: three ed25519 keys all typed `ed25519`, so two of the
    # three units are never created and their targets never written.
    duplicate-type-fails = let
      msgs = failedMessages (base {
        entries = [
          hostKey
          (deployKey // { type = "ed25519"; })
        ];
      });
    in {
      ok = mentions "same type" msgs;
      why = "two entries of one type must fail evaluation";
    };

    # The goal state: only real host keys, with distinct types.
    clean-manifest-passes = let
      msgs = failedMessages (base { entries = [ hostKey ecdsaKey ]; });
    in {
      ok = !(mentions "SSH host key" msgs);
      why = "ssh_host_* keys with distinct types must evaluate";
    };

    # An entry with no `type` is filtered out before it reaches sshd, so it is
    # unused rather than wrong -- and two of them do not collide.
    untyped-entries-pass = let
      msgs = failedMessages (base {
        entries = [
          hostKey
          {
            source = "ssh/initrd_ed25519_key.age";
            target = "initrd_ed25519_key";
          }
          {
            source = "ssh/deploy_ed25519_key.age";
            target = "deploy_ed25519_key";
          }
        ];
      });
    in {
      ok = !(mentions "SSH host key" msgs);
      why = "untyped entries must neither fail nor collide";
    };

    # A host mid-migration has to stay buildable, but it is about to be
    # flipped, so it has to be told -- the same trade ownership.nix makes.
    dry-run-warns-instead = let
      module = base {
        entries = [ hostKey deployKey ];
        dryRun = true;
      };
    in {
      ok = !(mentions "deploy_ed25519" (failedMessages module))
        && mentions "deploy_ed25519" (warningMessages module);
      why = "dry-run must warn about a bad key type, not fail the build";
    };
  };

  failed = lib.filterAttrs (_: case: !case.ok) cases;

in if failed != { } then
  throw ''
    aegis ssh-host-keys validation test failed:
    ${lib.concatStringsSep "\n"
    (lib.mapAttrsToList (name: case: "  ${name}: ${case.why}") failed)}
  ''
else
  pkgs.runCommand "aegis-ssh-host-keys-test" { } ''
    echo "ssh-host-keys validation: ${
      toString (lib.length (lib.attrNames cases))
    } cases passed"
    touch $out
  ''
