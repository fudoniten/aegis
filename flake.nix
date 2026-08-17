{
  description = "Aegis - Encrypted secrets management for NixOS";

  inputs = { nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05"; };

  outputs = { self, nixpkgs, ... }: {
    # NixOS modules
    nixosModules = {
      # Core secrets module: reads deploy/hosts/<host>/secrets.toml
      secrets = import ./modules/secrets.nix;

      # KDC database management from the per-realm principal bundle
      kdc = import ./modules/kdc.nix;

      # Deprecated compatibility shim for the old aegis.autoSecrets options
      autoSecrets = import ./modules/auto-secrets.nix;

      # Default: the core module plus the deprecated shim, so existing
      # configurations keep evaluating while they migrate.
      default = {
        imports = [ ./modules/secrets.nix ./modules/auto-secrets.nix ];
      };
    };

    # Home Manager modules
    homeManagerModules = {
      userSecrets = import ./modules/home-secrets.nix;
      default = import ./modules/home-secrets.nix;
    };

    # For testing
    checks = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (system:
      let pkgs = import nixpkgs { inherit system; };
      in {
        # Basic module evaluation test
        moduleEval = pkgs.runCommand "aegis-module-eval-test" { } ''
          echo "Module files exist:"
          test -f ${./modules/secrets.nix}
          test -f ${./modules/auto-secrets.nix}
          test -f ${./modules/home-secrets.nix}
          test -f ${./modules/kdc.nix}
          echo "OK"
          touch $out
        '';

        # NixOS VM tests (only on x86_64-linux for speed)
      } // (if system == "x86_64-linux" then {
        # Basic secret decryption
        basic = import ./tests/basic.nix { inherit pkgs; };

        # Two-phase decryption (role keys)
        two-phase = import ./tests/two-phase.nix { inherit pkgs; };

        # Service dependency on secrets
        service-dependency =
          import ./tests/service-dependency.nix { inherit pkgs; };

        # Manifest-driven deployment: target paths, ownership, modes, the
        # legacy base64 keytab wrapper, and sshd ordering
        manifest = import ./tests/manifest.nix { inherit pkgs; };

        # Secrets encrypted to a role: one shared ciphertext, decrypted in
        # phase 2 with the role key the host unwrapped in phase 1
        role-secret = import ./tests/role-secret.nix { inherit pkgs; };

        # A secret owned by a user or group the host does not declare fails
        # evaluation instead of failing chown at boot. Evaluation-only.
        ownership =
          import ./tests/ownership.nix { inherit pkgs nixpkgs system; };

        # An [[ssh-host-keys]] entry that cannot be an sshd identity -- a type
        # ssh-keygen does not have, or a type shared with another entry --
        # fails evaluation instead of reaching sshd. Evaluation-only.
        ssh-host-keys =
          import ./tests/ssh-host-keys.nix { inherit pkgs nixpkgs system; };
      } else
        { }));
  };
}
