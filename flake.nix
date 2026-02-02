{
  description = "Development shell for FPVM";

  # Nixpkgs version to use
  inputs.nixpkgs.url = "nixpkgs/nixos-25.11";

  outputs = { self, nixpkgs }:
    let
      # System types to support.
      # I have only ever tested this on x86_64-linux, so we limit to that.
      supportedSystems = [ "x86_64-linux" ]; # "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });

    in
      {
        # This flake does not provide any packages
        packages = {};

        # This flake does not provide any packages, so it cannot have apps
        # either.
        # apps is meant to play with the "nix run" command.
        apps = {};

        # What we really want
        devShells = forAllSystems (system:
          let pkgs = nixpkgsFor.${system};
              pythonEnv = pkgs.python3.withPackages (ps: with ps; [
                pandas
                lief
              ]);

          in {
            default = pkgs.mkShell {
              # nativeBuildInputs = riscvNativeBuildInputs;
              buildInputs = with pkgs; [
                pythonEnv
                # keep this line if you use bash
                bashInteractive
              ];

              # Ensure locales are present
              LOCALE_ARCHIVE = "${pkgs.glibcLocales}/lib/locale/locale-archive";

              hardeningDisable = [ "all" ];

              shellHook = ''
              '';
            };
          });
      };
}
