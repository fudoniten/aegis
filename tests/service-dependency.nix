# Test that services can depend on aegis secrets
{ pkgs, ... }:

let
  testKeyPair =
    pkgs.runCommand "test-keypair" { buildInputs = [ pkgs.age ]; } ''
      mkdir -p $out
      age-keygen -o $out/key.txt 2>/dev/null
      age-keygen -y $out/key.txt > $out/pubkey.txt
    '';

  testSecret = pkgs.runCommand "test-secret" { buildInputs = [ pkgs.age ]; } ''
    mkdir -p $out
    echo "service-config-data" | age -r "$(cat ${testKeyPair}/pubkey.txt)" -a -o $out/config.age
  '';

in pkgs.nixosTest {
  name = "aegis-service-dependency";

  nodes.machine = { config, pkgs, lib, ... }: {
    imports = [ ../modules/secrets.nix ];

    system.activationScripts.aegis-test-key = ''
      mkdir -p /var/lib/aegis
      cp ${testKeyPair}/key.txt /var/lib/aegis/master-key
      chmod 400 /var/lib/aegis/master-key
    '';

    aegis.secrets = {
      enable = true;
      masterKeyPath = "/var/lib/aegis/master-key";

      secrets.service-config = {
        source = "${testSecret}/config.age";
        target = "/run/aegis/service-config";
        phase = 1;
      };
    };

    # A service that depends on the secret
    systemd.services.test-service = {
      description = "Test service that needs secrets";
      after = [ "aegis-secrets.target" ];
      requires = [ "aegis-secrets.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "test-service-start" ''
          # Verify the secret exists before we run
          if [ ! -f /run/aegis/service-config ]; then
            echo "Secret not found!" >&2
            exit 1
          fi

          # Read the secret
          CONFIG=$(cat /run/aegis/service-config)
          echo "Service started with config: $CONFIG"

          # Write a marker file to prove we ran
          echo "started" > /tmp/test-service-ran
        '';
      };
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("aegis-secrets.target")
    machine.wait_for_unit("test-service.service")

    # Verify the service ran successfully
    machine.succeed("test -f /tmp/test-service-ran")
    output = machine.succeed("cat /tmp/test-service-ran")
    assert "started" in output

    # Verify the secret was available
    machine.succeed("test -f /run/aegis/service-config")

    print("Service dependency test passed!")
  '';
}
