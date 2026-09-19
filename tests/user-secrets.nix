# User secrets: what a user put in their own repo, decrypted on a host they
# are entitled to.
#
# This is the path that has never worked. The module used to generate a phase-1
# unit for users/<name>/.key.age -- a per-user deployment key from PLAN.md that
# aegis-tools-system never emitted -- and a phase-2 unit that `Requires=` it,
# so nothing ran. `aegis build user-secrets` encrypts the manifest and every
# secret to the host master key, exactly like any other host secret, so that is
# what this test builds and what the module now reads.
{ pkgs, ... }:

let
  masterKey =
    pkgs.runCommand "master-keypair" { buildInputs = [ pkgs.age ]; } ''
      mkdir -p $out
      age-keygen -o $out/key.txt 2>/dev/null
      age-keygen -y $out/key.txt > $out/pubkey.txt
    '';

  # The hashed filenames are the point of the layout: the ciphertext on a host
  # does not reveal what the secret is called. The manifest -- itself
  # encrypted -- is the only thing that maps them back.
  repoTree = pkgs.runCommand "aegis-deploy-tree" {
    buildInputs = [ pkgs.age pkgs.coreutils ];
  } ''
    mkdir -p $out/deploy/hosts/machine/users/testuser/secrets

    MASTER_PUB="$(cat ${masterKey}/pubkey.txt)"
    USERDIR=$out/deploy/hosts/machine/users/testuser

    printf 'ghp_secret_value' \
      | age -r "$MASTER_PUB" -a -o $USERDIR/secrets/aaaa1111.age
    printf 'contents of a file secret' \
      | age -r "$MASTER_PUB" -a -o $USERDIR/secrets/bbbb2222.age
    printf 'placed-at-an-explicit-target' \
      | age -r "$MASTER_PUB" -a -o $USERDIR/secrets/cccc3333.age

    age -r "$MASTER_PUB" -a -o $USERDIR/manifest.age <<'EOF'
    secrets:
      aaaa1111.age:
        name: GITHUB_TOKEN
        type: env
        created: 2026-09-18T00:00:00+00:00
      bbbb2222.age:
        name: aws-creds
        type: file
        created: 2026-09-18T00:00:00+00:00
      cccc3333.age:
        name: targeted
        type: file
        target: /run/testuser-config/token
        mode: "0400"
        created: 2026-09-18T00:00:00+00:00
    EOF

    # A host secret alongside them, so the test also covers the two kinds
    # coexisting rather than user secrets in isolation.
    printf 'host-value' \
      | age -r "$MASTER_PUB" -a -o $out/deploy/hosts/machine/own.age

    cat > $out/deploy/hosts/machine/secrets.toml <<EOF
    [secrets.own-token]
    source = "own.age"
    target = "/run/aegis/secrets/own-token"
    user = "root"
    group = "root"
    mode = "0400"
    EOF
  '';

in pkgs.testers.nixosTest {
  name = "aegis-user-secrets";

  nodes.machine = { ... }: {
    imports = [ ../modules/secrets.nix ];

    users.groups.testuser = { };
    users.users.testuser = {
      isNormalUser = true;
      group = "testuser";
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
      users = [ "testuser" ];
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("aegis-phase1.target")
    machine.wait_for_unit("aegis-phase2.target")
    machine.wait_for_unit("aegis-user-secrets-testuser.service")

    # --- Environment variables land one file per name, under env/
    token = machine.succeed("cat /run/aegis/users/testuser/env/GITHUB_TOKEN")
    assert token == "ghp_secret_value", f"unexpected env secret: {token!r}"

    # --- Files with no target land under files/, named as the user named them
    creds = machine.succeed("cat /run/aegis/users/testuser/files/aws-creds")
    assert creds == "contents of a file secret", f"unexpected file secret: {creds!r}"

    # --- A manifest entry carrying a target is placed there instead
    targeted = machine.succeed("cat /run/testuser-config/token")
    assert targeted == "placed-at-an-explicit-target", (
        f"target field ignored: {targeted!r}")

    # --- Everything is the user's, and unreadable to anyone else
    for path in [
        "/run/aegis/users/testuser",
        "/run/aegis/users/testuser/env",
        "/run/aegis/users/testuser/env/GITHUB_TOKEN",
        "/run/aegis/users/testuser/files/aws-creds",
    ]:
        owner = machine.succeed(f"stat -c %U {path}").strip()
        assert owner == "testuser", f"{path} owned by {owner}, not testuser"

    machine.succeed("test $(stat -c %a /run/aegis/users/testuser) = 700")
    machine.succeed("test $(stat -c %a /run/aegis/users/testuser/env/GITHUB_TOKEN) = 400")

    # ...and really is readable by them, which is the whole point. A
    # root-owned 0400 file in a 0700 root directory would pass every check
    # above and still be useless.
    machine.succeed(
        "su testuser -c 'cat /run/aegis/users/testuser/env/GITHUB_TOKEN' >/dev/null")

    # --- There is no user deployment key any more
    machine.fail("test -e /run/aegis/users/testuser/.key")
    machine.fail("systemctl cat aegis-user-key-testuser.service")

    # --- Host secrets are unaffected
    own = machine.succeed("cat /run/aegis/secrets/own-token")
    assert own == "host-value", f"unexpected host secret: {own!r}"

    # --- A secret removed from the user's repo must stop working on hosts
    # that already have it. The manifest is the only record of what should be
    # present, so anything else under env/ or files/ is stale by definition.
    machine.succeed("touch /run/aegis/users/testuser/env/REVOKED_TOKEN")
    machine.succeed("systemctl restart aegis-user-secrets-testuser.service")
    machine.fail("test -e /run/aegis/users/testuser/env/REVOKED_TOKEN")
    machine.succeed("test -e /run/aegis/users/testuser/env/GITHUB_TOKEN")
  '';
}
