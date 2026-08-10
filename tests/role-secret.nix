# Role secrets: one ciphertext, shared by every member of a role.
#
# This is the layout `aegis secret import --role` produces. Unlike a host
# secret, the file does not live under the host at all: the manifest points
# out of the host directory at deploy/roles/<role>/secrets/<name>.age, and the
# host reads it with the role key it unwrapped in phase 1. Adding a host to
# the role is then the whole of "give this host the secret" -- nothing is
# re-encrypted, and the plaintext is never needed again.
{ pkgs, ... }:

let
  masterKey =
    pkgs.runCommand "master-keypair" { buildInputs = [ pkgs.age ]; } ''
      mkdir -p $out
      age-keygen -o $out/key.txt 2>/dev/null
      age-keygen -y $out/key.txt > $out/pubkey.txt
    '';

  roleKey =
    pkgs.runCommand "role-keypair" { buildInputs = [ pkgs.age ]; } ''
      mkdir -p $out
      age-keygen -o $out/key.txt 2>/dev/null
      age-keygen -y $out/key.txt > $out/pubkey.txt
    '';

  # A stand-in for a whole aegis-secrets deploy/ tree, not just one host: the
  # relative source in the manifest is the point of the test, so the role
  # directory has to sit where the tools put it.
  repoTree = pkgs.runCommand "aegis-deploy-tree" {
    buildInputs = [ pkgs.age pkgs.coreutils ];
  } ''
    mkdir -p $out/deploy/hosts/machine/roles \
             $out/deploy/hosts/machine/secrets \
             $out/deploy/roles/svc/secrets

    MASTER_PUB="$(cat ${masterKey}/pubkey.txt)"
    ROLE_PUB="$(cat ${roleKey}/pubkey.txt)"

    # Phase 1: this host's copy of the role private key.
    age -r "$MASTER_PUB" -a \
      -o $out/deploy/hosts/machine/roles/svc.age < ${roleKey}/key.txt

    # Phase 2: the role's secret. Encrypted to the ROLE, so no host master key
    # can read it directly -- which is what makes it shareable.
    printf 'role-shared-value' \
      | age -r "$ROLE_PUB" -a -o $out/deploy/roles/svc/secrets/shared-token.age

    # An ordinary host secret alongside it, to prove the two kinds coexist and
    # that phase 1 is still used for the host's own material.
    printf 'host-only-value' \
      | age -r "$MASTER_PUB" -a -o $out/deploy/hosts/machine/secrets/own-token.age

    cat > $out/deploy/hosts/machine/secrets.toml <<EOF
    roles = ["svc"]

    [secrets.own-token]
    source = "secrets/own-token.age"
    target = "/run/svc/own-token"
    user = "root"
    group = "root"
    mode = "0400"

    [secrets.shared-token]
    source = "../../roles/svc/secrets/shared-token.age"
    target = "/run/svc/shared-token"
    user = "svcuser"
    group = "svcuser"
    mode = "0440"
    role = "svc"
    EOF
  '';

in pkgs.testers.nixosTest {
  name = "aegis-role-secret";

  nodes.machine = { config, pkgs, lib, ... }: {
    imports = [ ../modules/secrets.nix ];

    users.groups.svcuser = { };
    users.users.svcuser = {
      isSystemUser = true;
      group = "svcuser";
    };

    system.activationScripts.aegis-test-key = ''
      mkdir -p /var/lib/aegis
      cp ${masterKey}/key.txt /var/lib/aegis/master-key
      chmod 400 /var/lib/aegis/master-key
    '';

    aegis.secrets = {
      enable = true;
      dryRun = false;
      masterKeyPath = "/var/lib/aegis/master-key";
      secretsPath = "${repoTree}/deploy/hosts/machine";
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("aegis-phase1.target")
    machine.wait_for_unit("aegis-phase2.target")

    # --- The role key is unwrapped in phase 1, with the host master key
    machine.succeed("test -f /run/aegis/roles/svc")

    # --- The host's own secret still comes from the host directory
    own = machine.succeed("cat /run/svc/own-token")
    assert own == "host-only-value", f"unexpected host secret: {own!r}"

    # --- The role secret is decrypted from the shared copy, with the role key
    shared = machine.succeed("cat /run/svc/shared-token")
    assert shared == "role-shared-value", f"unexpected role secret: {shared!r}"

    # ...and the manifest's ownership and mode are honoured for it too
    machine.succeed("test $(stat -c %U /run/svc/shared-token) = svcuser")
    machine.succeed("test $(stat -c %a /run/svc/shared-token) = 440")

    # --- It really is phase 2: the unit that decrypts it must not run until
    # the role key exists. Ordering after aegis-phase1.target alone is not
    # enough, because wantedBy is weak and the target activates even when a
    # member unit failed -- so the dependency on the role unit is explicit.
    after = machine.succeed("systemctl show aegis-secret-shared-token.service -p After")
    requires = machine.succeed(
        "systemctl show aegis-secret-shared-token.service -p Requires")
    assert "aegis-role-svc.service" in after, f"not ordered after role key: {after}"
    assert "aegis-role-svc.service" in requires, (
        f"only weakly depends on the role key: {requires}")

    # --- And that dependency is load-bearing: with the role key unavailable,
    # the role secret must fail to decrypt rather than deploy something stale
    # or empty.
    machine.succeed("systemctl stop aegis-secret-shared-token.service")
    machine.succeed("systemctl stop aegis-role-svc.service")
    machine.succeed("systemctl mask aegis-role-svc.service")
    machine.succeed("rm -f /run/aegis/roles/svc /run/svc/shared-token")

    machine.fail("systemctl start aegis-secret-shared-token.service")
    machine.fail("test -f /run/svc/shared-token")

    machine.succeed("systemctl unmask aegis-role-svc.service")
    machine.succeed("systemctl start aegis-role-svc.service")
    machine.succeed("systemctl start aegis-secret-shared-token.service")
    machine.succeed("test -f /run/svc/shared-token")

    print("Role secret test passed!")
  '';
}
