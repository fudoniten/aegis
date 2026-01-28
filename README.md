# Aegis - Encrypted Secrets Management for NixOS

Aegis provides encrypted secrets management with age encryption, two-phase decryption, and user self-service.

## Features

- **age encryption** - Simple, auditable, modern encryption
- **Two-phase decryption** - Host secrets first, then role/user secrets
- **User self-service** - Users manage their own secrets repos
- **Public repos** - All repos can be public (security through encryption)

## Quick Start

### 1. Add to your flake inputs

```nix
{
  inputs = {
    aegis.url = "github:fudoniten/aegis";
    aegis-secrets.url = "github:fudoniten/aegis-secrets";
  };
}
```

### 2. Import the module

```nix
{ inputs, ... }:

{
  imports = [ inputs.aegis.nixosModules.default ];

  aegis.autoSecrets = {
    enable = true;
    buildPath = "${inputs.aegis-secrets}/build/hosts/${config.networking.hostName}";
    masterKeyPath = "/var/lib/aegis/master-key";
    roles = [ ];  # e.g., [ "kdc" ] for the KDC server
    users = [ "niten" ];  # Users whose secrets to decrypt
  };
}
```

### 3. Or configure manually

```nix
{
  imports = [ inputs.aegis.nixosModules.secrets ];

  aegis.secrets = {
    enable = true;
    masterKeyPath = "/var/lib/aegis/master-key";

    secrets = {
      my-api-key = {
        source = ./secrets/my-api-key.age;
        target = "/run/aegis/my-api-key";
        user = "myservice";
        group = "myservice";
        permissions = "0400";
        phase = 1;
      };
    };

    sshKeys = {
      enable = true;
      source = ./secrets/ssh-keys.age;
    };

    keytab = {
      enable = true;
      source = ./secrets/keytab.age;
    };
  };
}
```

## Home Manager Integration

For user environment variables from secrets:

```nix
{ inputs, ... }:

{
  imports = [ inputs.aegis.homeManagerModules.default ];

  aegis.userSecrets = {
    enable = true;
    username = "niten";
    
    # Auto-export these secrets as environment variables
    sessionVariablesFromSecrets = [
      "GITHUB_TOKEN"
      "OPENAI_API_KEY"
    ];
  };
}
```

## Modules

### `aegis.secrets` (NixOS)

Core module for decrypting secrets on hosts.

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | bool | false | Enable Aegis secrets |
| `masterKeyPath` | string | "/var/lib/aegis/master-key" | Path to host's age private key |
| `secrets` | attrsOf secret | {} | Secrets to decrypt |
| `sshKeys.enable` | bool | false | Enable SSH key decryption |
| `keytab.enable` | bool | false | Enable Kerberos keytab decryption |
| `roles` | list of string | [] | Roles this host has |
| `users` | list of string | [] | Users whose secrets to decrypt |

**Secret options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `source` | path | - | Path to encrypted .age file |
| `target` | string | /run/aegis/<name> | Decryption target path |
| `user` | string | "root" | File owner |
| `group` | string | "root" | File group |
| `permissions` | string | "0400" | File permissions |
| `phase` | 1 or 2 | 1 | Decryption phase |
| `identity` | string | masterKeyPath | Path to decryption key |

### `aegis.autoSecrets` (NixOS)

Convenience wrapper that auto-discovers secrets from the build directory.

### `aegis.userSecrets` (Home Manager)

Module for exporting decrypted secrets as environment variables.

## Systemd Targets

- `aegis-phase1.target` - After host secrets are decrypted
- `aegis-phase2.target` - After role/user secrets are decrypted
- `aegis-secrets.target` - After all secrets are available

Services can depend on these targets:

```nix
systemd.services.myservice = {
  after = [ "aegis-secrets.target" ];
  requires = [ "aegis-secrets.target" ];
};
```

## Secret Paths

Decrypted secrets are placed in `/run/aegis/`:

```
/run/aegis/
  ssh-keys           # Host SSH keys
  keytab             # Kerberos keytab
  my-custom-secret   # Custom secrets
  roles/
    kdc              # KDC role key (for phase 2)
  users/
    niten/
      .key           # User deployment key
      env/
        GITHUB_TOKEN # User env vars
      files/
        aws-creds    # User files
```

## Two-Phase Decryption

**Phase 1** (with host master key):
- Host secrets (SSH keys, keytab, etc.)
- Role keys (if this host has roles)
- User deployment keys

**Phase 2** (with keys from phase 1):
- Role-specific secrets (using role key)
- User secrets (using user deployment key)

This allows the KDC to decrypt all host keytabs (using kdc role key), while each host can only decrypt its own keytab (using host master key).

## See Also

- [PLAN.md](./PLAN.md) - Complete architecture and implementation details
- [aegis-tools-system](../aegis-tools-system) - Admin CLI tools
- [aegis-tools-user](../aegis-tools-user) - User CLI tools
