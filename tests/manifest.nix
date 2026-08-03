# Manifest-driven deployment: the module reads secrets.toml and honours the
# target paths, ownership and permissions recorded there.
#
# This is the path that aegis-tools-system actually produces, and the one that
# aegis.autoSecrets used to bypass.
{ pkgs, ... }:

let
  masterKey =
    pkgs.runCommand "master-keypair" { buildInputs = [ pkgs.age ]; } ''
      mkdir -p $out
      age-keygen -o $out/key.txt 2>/dev/null
      age-keygen -y $out/key.txt > $out/pubkey.txt
    '';

  # A stand-in for deploy/hosts/<hostname>/, laid out exactly as the tools
  # write it, including a keytab carrying the legacy base64: wrapper.
  hostSecrets = pkgs.runCommand "host-secrets" {
    buildInputs = [ pkgs.age pkgs.openssh pkgs.coreutils ];
  } ''
    mkdir -p $out/ssh $out/secrets
    PUB="$(cat ${masterKey}/pubkey.txt)"

    # SSH host key pair
    ssh-keygen -t ed25519 -N "" -C host@testmachine -f ./ssh_host_ed25519_key
    age -r "$PUB" -a -o $out/ssh/ssh_host_ed25519_key.age < ./ssh_host_ed25519_key
    cp ./ssh_host_ed25519_key.pub $out/ssh/ssh_host_ed25519_key.pub

    # A keytab written by the OLD tooling: base64-encoded with a sentinel.
    # The module must unwrap it; before the fix it deployed the literal
    # string "base64:..." instead of keytab bytes.
    printf 'KEYTAB-BINARY-CONTENT' > ./keytab.raw
    printf 'base64:' > ./keytab.wrapped
    base64 -w0 < ./keytab.raw >> ./keytab.wrapped
    age -r "$PUB" -a -o $out/keytab.age < ./keytab.wrapped

    # A generic secret with a non-default owner and mode
    printf 'service-token-value' | age -r "$PUB" -a -o $out/secrets/svc-token.age

    cat > $out/secrets.toml <<EOF
    [[ssh-host-keys]]
    source = "ssh/ssh_host_ed25519_key.age"
    target = "ssh_host_ed25519_key"
    target_dir = "/etc/ssh"
    user = "root"
    group = "root"
    mode = "0600"
    type = "ed25519"

    [keytab]
    source = "keytab.age"
    target = "/etc/krb5.keytab"
    user = "root"
    group = "root"
    mode = "0600"
    encoding = "base64"

    [secrets.svc-token]
    source = "secrets/svc-token.age"
    target = "/run/svc/token"
    user = "svcuser"
    group = "svcuser"
    mode = "0400"
    EOF
  '';

in pkgs.testers.nixosTest {
  name = "aegis-manifest";

  nodes.machine = { config, pkgs, lib, ... }: {
    imports = [ ../modules/secrets.nix ];

    # sshd must really be enabled: the behaviour under test is NixOS's
    # preStart generating a replacement key when hostKeys points at a missing
    # file, which only happens for a configured, enabled server.
    services.openssh = {
      enable = true;
      hostKeys = [{
        path = "/etc/ssh/ssh_host_ed25519_key";
        type = "ed25519";
      }];
    };

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
      secretsPath = hostSecrets;
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("aegis-phase1.target")

    # --- SSH host keys land where the manifest says, not /run/aegis
    machine.succeed("test -f /etc/ssh/ssh_host_ed25519_key")
    machine.succeed("test $(stat -c %a /etc/ssh/ssh_host_ed25519_key) = 600")
    # ...and the public key ships alongside it
    machine.succeed("test -f /etc/ssh/ssh_host_ed25519_key.pub")
    machine.succeed("grep -q '^ssh-ed25519 ' /etc/ssh/ssh_host_ed25519_key.pub")

    # --- The keytab is decoded, not deployed as "base64:..."
    machine.succeed("test -f /etc/krb5.keytab")
    keytab = machine.succeed("cat /etc/krb5.keytab")
    assert keytab == "KEYTAB-BINARY-CONTENT", f"keytab not decoded: {keytab!r}"
    assert not keytab.startswith("base64:"), "base64 sentinel was not stripped"

    # --- Ownership and mode from the manifest are applied
    machine.succeed("test -f /run/svc/token")
    machine.succeed("test $(stat -c %U /run/svc/token) = svcuser")
    machine.succeed("test $(stat -c %a /run/svc/token) = 400")
    token = machine.succeed("cat /run/svc/token")
    assert "service-token-value" in token, f"unexpected content: {token!r}"

    # --- sshd depends on the units that decrypt its keys, not just the phase
    # target. wantedBy is a weak dependency, so the target activates even when
    # a key unit has failed.
    after = machine.succeed("systemctl show sshd.service -p After")
    requires = machine.succeed("systemctl show sshd.service -p Requires")
    assert "aegis-ssh-ed25519.service" in after, f"sshd not ordered after key unit: {after}"
    assert "aegis-ssh-ed25519.service" in requires, (
        f"sshd only weakly depends on its host key: {requires}")

    # --- and that dependency is load-bearing. With the key unit unable to run
    # and the key absent, sshd must refuse to start rather than let NixOS's
    # preStart mint a replacement identity. This is the failure mode that a
    # target under /run makes reachable on every boot.
    machine.succeed("systemctl stop sshd.service")
    machine.succeed("systemctl mask aegis-ssh-ed25519.service")
    machine.succeed("rm -f /etc/ssh/ssh_host_ed25519_key")

    machine.fail("systemctl start sshd.service")
    machine.fail("test -f /etc/ssh/ssh_host_ed25519_key")
    print("sshd refused to start without its key, and generated nothing")

    # ...and recovers cleanly once the key unit can run again
    machine.succeed("systemctl unmask aegis-ssh-ed25519.service")
    machine.succeed("systemctl start aegis-ssh-ed25519.service")
    machine.succeed("systemctl start sshd.service")
    machine.succeed("test -f /etc/ssh/ssh_host_ed25519_key")

    print("Manifest test passed!")
  '';
}
