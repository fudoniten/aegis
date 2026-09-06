# `runtimePath`: ciphertext is read from a path outside the store, so it can be
# deployed on its own instead of riding along in the system closure.
#
# Three things are worth proving, and they do not all fit one kind of test:
#
#   1. It still works.  Secrets decrypt when the .age files arrive through a
#      symlink that did not exist at build time -- including role secrets,
#      which reach a shared ciphertext by climbing out of the host directory
#      (`../../roles/<role>/secrets/<name>.age`), and so depend on the whole
#      `hosts/` + `roles/` geometry being reproduced under `runtimePath`.
#
#   2. Rotation needs no system generation.  Repointing the link at a tree
#      with new ciphertext and restarting the unit picks the new value up.
#      That is exactly what deploying the profile on its own does, and it is
#      the entire reason for the option.
#
#   3. It bought something.  The decrypt scripts must no longer name the
#      secrets tree at all, or the ciphertext is still in the closure and
#      nothing has been gained.  A property of the generated script rather
#      than of a running machine, so it is a build-time grep.
#
# Returns both tests; flake.nix registers them separately.
{ pkgs, nixpkgs, system }:

let
  inherit (nixpkgs) lib;

  keys = pkgs.runCommand "aegis-test-keys" { nativeBuildInputs = [ pkgs.age ]; } ''
    mkdir -p $out
    age-keygen -o $out/host.key 2>/dev/null
    age-keygen -y $out/host.key > $out/host.pub
    age-keygen -o $out/role.key 2>/dev/null
    age-keygen -y $out/role.key > $out/role.pub
  '';

  # A miniature aegis-secrets `deploy/` tree: one host with a host-encrypted
  # secret, a wrapped role key, and a role secret shared via ../../roles.
  # `hostValue` is what the host-encrypted secret decrypts to, so the same
  # builder can produce the "rotated" tree for point 2.
  mkTree = { name, hostValue }:
    pkgs.runCommand name { nativeBuildInputs = [ pkgs.age ]; } ''
      host="$out/hosts/testhost"
      mkdir -p "$host/roles" "$out/roles/testrole/secrets"

      # Encrypted to the host's own master key (phase 1).
      echo -n "${hostValue}" \
        | age -r "$(cat ${keys}/host.pub)" -a -o "$host/host-thing.age"

      # The role's private key, wrapped to the host (phase 1), so the host can
      # use it to open the shared secret below (phase 2).
      age -r "$(cat ${keys}/host.pub)" -a \
        -o "$host/roles/testrole.age" < ${keys}/role.key

      # One shared ciphertext, encrypted to the role, living outside the host
      # directory exactly as the real repo has it.
      echo -n "role-secret-value" \
        | age -r "$(cat ${keys}/role.pub)" -a \
          -o "$out/roles/testrole/secrets/shared.age"

      cp ${manifest} "$host/secrets.toml"
    '';

  manifest = pkgs.writeText "secrets.toml" ''
    roles = ["testrole"]

    [secrets.host-thing]
    source = "host-thing.age"
    target = "/run/aegis/secrets/host-thing"
    user = "root"
    group = "root"
    mode = "0400"

    [secrets.shared]
    source = "../../roles/testrole/secrets/shared.age"
    target = "/run/aegis/secrets/shared"
    user = "root"
    group = "root"
    mode = "0400"
    role = "testrole"
  '';

  tree = mkTree {
    name = "aegis-test-tree";
    hostValue = "host-secret-value";
  };

  # Same manifest, different ciphertext -- a rotation, which is the case the
  # separate profile exists to make cheap.
  rotatedTree = mkTree {
    name = "aegis-test-tree-rotated";
    hostValue = "host-secret-rotated";
  };

  # Where the deploy-rs profile would be linked.  Nothing about this path
  # exists at build time, which is the point.
  runtimePath = "/run/aegis-profile";

  machine = { ... }: {
    imports = [ ../modules/secrets.nix ];

    boot.loader.grub.enable = false;
    fileSystems."/" = {
      device = "/dev/vda";
      fsType = "ext4";
    };
    system.stateVersion = lib.trivial.release;
    networking.hostName = "testhost";

    # Stand in for the deploy-rs profile link, and for the master key that
    # profiles/common.nix generates on a real host.
    system.activationScripts.aegis-test-fixture = ''
      mkdir -p /var/lib/aegis
      cp ${keys}/host.key /var/lib/aegis/master-key
      chmod 0400 /var/lib/aegis/master-key
      ln -sfn ${tree} ${runtimePath}
    '';

    aegis.secrets = {
      enable = true;
      dryRun = false;
      masterKeyPath = "/var/lib/aegis/master-key";

      # The manifest is read from the store; the ciphertext from the profile.
      secretsPath = "${tree}/hosts/testhost";
      inherit runtimePath;
    };
  };

  evaluated = (import "${nixpkgs}/nixos/lib/eval-config.nix" {
    inherit system;
    modules = [ machine ];
  }).config;

  decryptScripts = map (name:
    evaluated.systemd.services."aegis-${name}".serviceConfig.ExecStart) [
      "secret-host-thing"
      "secret-shared"
      "role-testrole"
    ];

  # The tree's store path as inert text, so grepping for it does not itself
  # create the dependency under test.
  treePath = builtins.unsafeDiscardStringContext "${tree}";

in {
  vm = pkgs.testers.nixosTest {
    name = "aegis-runtime-path";

    nodes.machine = machine;

    testScript = ''
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("aegis-phase1.target")
      machine.wait_for_unit("aegis-phase2.target")

      # Phase 1, decrypted with the host master key, through the profile link.
      assert machine.succeed("cat /run/aegis/secrets/host-thing") == "host-secret-value"

      # Phase 2. The shared ciphertext lives outside the host directory, so
      # this only works if roles/ was reproduced under runtimePath alongside
      # hosts/ and the manifest's ../.. resolves there.
      assert machine.succeed("cat /run/aegis/secrets/shared") == "role-secret-value"
      machine.succeed("test $(stat -c %a /run/aegis/secrets/shared) = 400")

      # The unit really is reading from outside the store.
      machine.succeed(
          "systemctl cat aegis-secret-host-thing.service | grep -q ${runtimePath}"
      )

      # Rotation: repoint the link and restart the unit. No new system
      # generation, no switch -- which is what deploying the profile alone
      # amounts to.
      machine.succeed("ln -sfn ${rotatedTree} ${runtimePath}")
      machine.succeed("systemctl restart aegis-secret-host-thing.service")
      assert machine.succeed("cat /run/aegis/secrets/host-thing") == "host-secret-rotated"

      print("runtime-path test passed!")
    '';
  };

  # Evaluation/build-time: the option has to actually take the ciphertext out
  # of the closure, or it is just an indirection.
  closure = pkgs.runCommand "aegis-runtime-path-closure" { } ''
    fail=0
    for script in ${lib.escapeShellArgs decryptScripts}; do
      echo "checking $script"
      if grep -q -- '${treePath}' "$script"; then
        echo "FAIL: $script still names ${treePath}," >&2
        echo "      so the ciphertext remains in the system closure." >&2
        fail=1
      fi
      if ! grep -q -- '${runtimePath}/hosts/testhost' "$script"; then
        echo "FAIL: $script does not read through ${runtimePath}." >&2
        fail=1
      fi
    done
    [ $fail -eq 0 ] || exit 1

    # The manifest fingerprint is what lets the profile's activation refuse to
    # install ciphertext this generation was not built for.
    test -n '${evaluated.environment.etc."aegis/manifest.sha256".text}'

    echo OK > $out
  '';
}
