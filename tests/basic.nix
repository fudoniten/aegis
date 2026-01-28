# Basic test: secrets are decrypted correctly
{ pkgs, ... }:

let
  # Generate a test keypair at build time
  testKeyPair =
    pkgs.runCommand "test-keypair" { buildInputs = [ pkgs.age ]; } ''
      mkdir -p $out
      age-keygen -o $out/key.txt 2> $out/pubkey.txt
      # Extract just the public key
      grep "^age1" $out/pubkey.txt > $out/pubkey.txt.tmp || age-keygen -y $out/key.txt > $out/pubkey.txt.tmp
      mv $out/pubkey.txt.tmp $out/pubkey.txt
    '';

  # Encrypt a test secret
  testSecret = pkgs.runCommand "test-secret" { buildInputs = [ pkgs.age ]; } ''
    mkdir -p $out
    echo "super-secret-value" | age -r "$(cat ${testKeyPair}/pubkey.txt)" -a -o $out/secret.age
  '';

in pkgs.nixosTest {
  name = "aegis-basic";

  nodes.machine = { config, pkgs, lib, ... }: {
    imports = [ ../modules/secrets.nix ];

    # Copy test key to the machine
    system.activationScripts.aegis-test-key = ''
      mkdir -p /var/lib/aegis
      cp ${testKeyPair}/key.txt /var/lib/aegis/master-key
      chmod 400 /var/lib/aegis/master-key
    '';

    aegis.secrets = {
      enable = true;
      masterKeyPath = "/var/lib/aegis/master-key";

      secrets.test-secret = {
        source = "${testSecret}/secret.age";
        target = "/run/aegis/test-secret";
        user = "root";
        group = "root";
        permissions = "0400";
        phase = 1;
      };
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("aegis-phase1.target")

    # Check the secret was decrypted
    machine.succeed("test -f /run/aegis/test-secret")

    # Check the content
    output = machine.succeed("cat /run/aegis/test-secret")
    assert "super-secret-value" in output, f"Expected secret content, got: {output}"

    # Check permissions
    machine.succeed("test $(stat -c %a /run/aegis/test-secret) = 400")

    # Check ownership
    machine.succeed("test $(stat -c %U /run/aegis/test-secret) = root")

    print("Basic test passed!")
  '';
}
