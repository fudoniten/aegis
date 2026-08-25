# Named keytabs: an arbitrary principal list, delivered to a host or a role.
#
# The host's own keytab is the [keytab] section and holds its service
# principals. A named keytab lives in the [keytabs] table instead, and exists
# because the interesting cases are not "this host proving it is itself": a
# client identity, a principal borrowed from elsewhere, a service keytab that
# moves between machines with its service.
#
# Both delivery modes are exercised here, because they take different paths
# through the module: a host-delivered keytab is phase 1 with the master key,
# a role-delivered one is phase 2 with the role key, and only the second can
# follow a service between hosts.
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

  repoTree = pkgs.runCommand "aegis-deploy-tree" {
    buildInputs = [ pkgs.age pkgs.coreutils ];
  } ''
    mkdir -p $out/deploy/hosts/machine/roles \
             $out/deploy/hosts/machine/keytabs \
             $out/deploy/roles/agent/keytabs

    MASTER_PUB="$(cat ${masterKey}/pubkey.txt)"
    ROLE_PUB="$(cat ${roleKey}/pubkey.txt)"

    age -r "$MASTER_PUB" -a \
      -o $out/deploy/hosts/machine/roles/agent.age < ${roleKey}/key.txt

    # Stand-ins for real keytabs: the module treats them as opaque bytes, so
    # what is asserted is placement, ownership and ordering -- not Kerberos.
    printf 'host-delivered-keytab' \
      | age -r "$MASTER_PUB" -a -o $out/deploy/hosts/machine/keytabs/backup.age

    printf 'role-delivered-keytab' \
      | age -r "$ROLE_PUB" -a -o $out/deploy/roles/agent/keytabs/hermes.age

    # The host's own keytab, to prove [keytab] and [keytabs] coexist rather
    # than one shadowing the other.
    printf 'host-own-keytab' \
      | age -r "$MASTER_PUB" -a -o $out/deploy/hosts/machine/keytab.age

    cat > $out/deploy/hosts/machine/secrets.toml <<EOF
    roles = ["agent"]

    [keytab]
    source = "keytab.age"
    target = "/run/aegis/keytab"
    user = "root"
    group = "root"
    mode = "0600"

    [keytabs.backup]
    source = "keytabs/backup.age"
    target = "/run/aegis/keytabs/backup"
    user = "root"
    group = "root"
    mode = "0600"

    [keytabs.hermes]
    source = "../../roles/agent/keytabs/hermes.age"
    target = "/run/hermes/krb5.keytab"
    user = "hermes"
    group = "hermes"
    mode = "0400"
    role = "agent"
    EOF
  '';

in pkgs.testers.nixosTest {
  name = "aegis-named-keytab";

  nodes.machine = { config, pkgs, lib, ... }: {
    imports = [ ../modules/secrets.nix ];

    users.groups.hermes = { };
    users.users.hermes = {
      isSystemUser = true;
      group = "hermes";
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

    # Referring to a named keytab by name rather than by path is the whole
    # reason `targets` exists; a typo here fails the build rather than the
    # service.
    environment.etc."hermes-keytab-path".text =
      config.aegis.secrets.manifest.targets.keytab-hermes;
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("aegis-phase1.target")
    machine.wait_for_unit("aegis-phase2.target")

    # --- The host keytab is untouched by the named ones
    own = machine.succeed("cat /run/aegis/keytab")
    assert own == "host-own-keytab", f"unexpected host keytab: {own!r}"

    # --- A host-delivered named keytab: phase 1, host master key
    backup = machine.succeed("cat /run/aegis/keytabs/backup")
    assert backup == "host-delivered-keytab", f"unexpected: {backup!r}"

    # --- A role-delivered one: phase 2, role key, and the manifest's
    # ownership honoured so the agent can actually read it
    hermes = machine.succeed("cat /run/hermes/krb5.keytab")
    assert hermes == "role-delivered-keytab", f"unexpected: {hermes!r}"
    machine.succeed("test $(stat -c %U /run/hermes/krb5.keytab) = hermes")
    machine.succeed("test $(stat -c %a /run/hermes/krb5.keytab) = 400")

    # --- manifest.targets names it, so config can refer to it symbolically
    path = machine.succeed("cat /etc/hermes-keytab-path").strip()
    assert path == "/run/hermes/krb5.keytab", f"unexpected target: {path!r}"

    # --- The role-delivered keytab depends on the role key directly, not just
    # on the phase target: wantedBy is weak, so the target would activate even
    # with the role key missing and deploy nothing where the agent expects it.
    requires = machine.succeed(
        "systemctl show aegis-keytab-hermes.service -p Requires")
    assert "aegis-role-agent.service" in requires, (
        f"only weakly depends on the role key: {requires}")

    # --- And the host-delivered one does not: it needs no role at all.
    backup_requires = machine.succeed(
        "systemctl show aegis-keytab-backup.service -p Requires")
    assert "aegis-role-agent.service" not in backup_requires, (
        f"host keytab should not depend on a role: {backup_requires}")

    print("Named keytab test passed!")
  '';
}
