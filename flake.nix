{
  description = "Aegis - Encrypted secrets management for NixOS";

  inputs = { nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11"; };

  outputs = { self, nixpkgs, ... }: {
    # NixOS modules
    nixosModules = {
      # Core secrets module
      secrets = import ./modules/secrets.nix;

      # Auto-discovery module (convenience wrapper)
      autoSecrets = import ./modules/auto-secrets.nix;

      # Default includes both
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
      } else
        { }));
  };
}
