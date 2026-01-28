# Two-phase decryption test
# Phase 1: Decrypt a "role key" with master key
# Phase 2: Decrypt a "role secret" with the role key
{ pkgs, ... }:

let
  # Master key (host key)
  masterKeyPair =
    pkgs.runCommand "master-keypair" { buildInputs = [ pkgs.age ]; } ''
      mkdir -p $out
      age-keygen -o $out/key.txt 2>/dev/null
      age-keygen -y $out/key.txt > $out/pubkey.txt
    '';

  # Role key (will be decrypted in phase 1, used in phase 2)
  roleKeyPair =
    pkgs.runCommand "role-keypair" { buildInputs = [ pkgs.age ]; } ''
      mkdir -p $out
      age-keygen -o $out/key.txt 2>/dev/null
      age-keygen -y $out/key.txt > $out/pubkey.txt
    '';

  # Encrypt the role private key with master key (phase 1 secret)
  encryptedRoleKey =
    pkgs.runCommand "encrypted-role-key" { buildInputs = [ pkgs.age ]; } ''
      mkdir -p $out
      cat ${roleKeyPair}/key.txt | age -r "$(cat ${masterKeyPair}/pubkey.txt)" -a -o $out/role-key.age
    '';

  # Encrypt a secret with the role key (phase 2 secret)
  encryptedRoleSecret =
    pkgs.runCommand "encrypted-role-secret" { buildInputs = [ pkgs.age ]; } ''
      mkdir -p $out
      echo "role-secret-data" | age -r "$(cat ${roleKeyPair}/pubkey.txt)" -a -o $out/role-secret.age
    '';

in pkgs.nixosTest {
  name = "aegis-two-phase";

  nodes.machine = { config, pkgs, lib, ... }: {
    imports = [ ../modules/secrets.nix ];

    system.activationScripts.aegis-test-key = ''
      mkdir -p /var/lib/aegis
      cp ${masterKeyPair}/key.txt /var/lib/aegis/master-key
      chmod 400 /var/lib/aegis/master-key
    '';

    aegis.secrets = {
      enable = true;
      masterKeyPath = "/var/lib/aegis/master-key";

      secrets = {
        # Phase 1: Decrypt role key with master key
        role-key = {
          source = "${encryptedRoleKey}/role-key.age";
          target = "/run/aegis/roles/test-role";
          phase = 1;
        };

        # Phase 2: Decrypt role secret with role key
        role-secret = {
          source = "${encryptedRoleSecret}/role-secret.age";
          target = "/run/aegis/role-secret";
          phase = 2;
          identity = "/run/aegis/roles/test-role";
        };
      };
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # Wait for phase 1
    machine.wait_for_unit("aegis-phase1.target")
    print("Phase 1 complete")

    # Check role key was decrypted
    machine.succeed("test -f /run/aegis/roles/test-role")
    print("Role key exists")

    # Wait for phase 2
    machine.wait_for_unit("aegis-phase2.target")
    print("Phase 2 complete")

    # Check role secret was decrypted
    machine.succeed("test -f /run/aegis/role-secret")

    # Verify content
    output = machine.succeed("cat /run/aegis/role-secret")
    assert "role-secret-data" in output, f"Expected role secret, got: {output}"

    print("Two-phase test passed!")
  '';
}
