# User secrets: the layout `aegis build user-secrets` writes under
# deploy/hosts/<host>/users/<user>/, decrypted on the host with its master key
# into /run/aegis/users/<user>, owned by the user and their primary group.
#
# Covers the three things that kept this path from ever working: the identity
# (master key, not a per-user key nothing generated), manifest keys that name
# the ciphertext file exactly -- plus the old suffix-less form -- and the owner
# group (the account's primary group, not one named after the user).
{ pkgs, ... }:

let
  masterKey =
    pkgs.runCommand "master-keypair" { buildInputs = [ pkgs.age ]; } ''
      mkdir -p $out
      age-keygen -o $out/key.txt 2>/dev/null
      age-keygen -y $out/key.txt > $out/pubkey.txt
    '';

  hostSecrets = pkgs.runCommand "host-secrets" {
    buildInputs = [ pkgs.age pkgs.coreutils ];
  } ''
    mkdir -p $out/users/alice/secrets
    PUB="$(cat ${masterKey}/pubkey.txt)"

    # Host manifest: present, with nothing else for this host.
    echo "# no host secrets" > $out/secrets.toml

    # Current form: the manifest key is the file name.
    printf 'tok123' | age -r "$PUB" -a -o $out/users/alice/secrets/aaaa.age

    # Legacy form: key "bbbb" for a file written as bbbb.age.  Binary, so a
    # text round trip anywhere would show.
    head -c 256 /dev/urandom > blob.raw
    cp blob.raw $out/blob.expected
    age -r "$PUB" -o $out/users/alice/secrets/bbbb.age < blob.raw

    cat > manifest.yaml <<EOF
    secrets:
      aaaa.age:
        name: GITHUB_TOKEN
        type: env
      bbbb:
        name: blob
        type: file
    EOF
    age -r "$PUB" -a -o $out/users/alice/manifest.age < manifest.yaml
  '';

in pkgs.testers.nixosTest {
  name = "aegis-user-secrets";

  nodes.machine = { ... }: {
    imports = [ ../modules/secrets.nix ];

    system.activationScripts.aegis-test-key = ''
      mkdir -p /var/lib/aegis
      cp ${masterKey}/key.txt /var/lib/aegis/master-key
      chmod 400 /var/lib/aegis/master-key
    '';

    users.groups.fudo = { };
    users.users.alice = {
      isNormalUser = true;
      group = "fudo";
    };

    aegis.secrets = {
      enable = true;
      dryRun = false;
      masterKeyPath = "/var/lib/aegis/master-key";
      secretsPath = hostSecrets;
      users = [ "alice" ];
    };
  };

  testScript = ''
    machine.wait_for_unit("aegis-user-secrets-alice.service")
    machine.wait_for_unit("aegis-phase2.target")

    base = "/run/aegis/users/alice"

    assert machine.succeed(f"cat {base}/env/GITHUB_TOKEN") == "tok123"
    machine.succeed(f"cmp {base}/files/blob ${hostSecrets}/blob.expected")

    for path in [base, f"{base}/env", f"{base}/env/GITHUB_TOKEN", f"{base}/files/blob"]:
        owner = machine.succeed(f"stat -c %U:%G {path}").strip()
        assert owner == "alice:fudo", f"{path} owned by {owner}"

    assert machine.succeed(f"stat -c %a {base}/env/GITHUB_TOKEN").strip() == "400"

    # Readable by the user it belongs to, and nobody else.
    machine.succeed(f"su alice -s /bin/sh -c 'cat {base}/env/GITHUB_TOKEN'")

    # Env secrets are in the user's login environment with no per-user config.
    assert machine.succeed("su -l alice -c 'printf %s \"$GITHUB_TOKEN\"'") == "tok123"
  '';
}
